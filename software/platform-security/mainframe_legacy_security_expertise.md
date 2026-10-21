# Mainframe and Legacy Systems Security
## Staff-Level Technical Reference

---

## 1. What "mainframe / legacy" means in 2026

The word "mainframe" gets used to mean roughly "computer your bank still runs that you don't understand." That definition is fine for headlines and useless for threat modeling. This document covers four substrate threads that share an attribute — they predate Linux as the operational lingua franca and they still run an enormous share of consequential transaction load — but otherwise have different architectures, different auth models, different attack surfaces, and different research communities.

**IBM Z (z/OS)** is IBM's flagship architecture descended from the 1964 System/360. Current hardware is the z16 (2022) and z17 (announced April 2025, GA June 2025); current OS is z/OS 3.1 (2023) with z/OS 3.2 announced for late 2025. By IBM's own marketing, z mainframes process the majority of credit-card transactions worldwide and run the back-office of the largest banks, insurance carriers, brokerages, government tax systems, and social-insurance agencies. IBM's specific numbers ("70% of Fortune 500 mainframe-resident workload," "two-thirds of global credit-card transactions") are vendor-supplied and not independently verified — but the directional claim that z/OS sits behind a structurally important fraction of global finance is uncontested.

**IBM i** (formerly OS/400, AS/400, iSeries, System i) is IBM's midrange business platform. Launched 1988 as the AS/400, runs on POWER hardware (Power9, Power10, Power11), current OS is IBM i 7.5 (2022) and 7.6 (announced 2025). The integrated DB2 for i + RPG + COBOL stack is the spine of countless small-to-mid manufacturing, distribution, insurance, and ERP installations worldwide. The footprint is smaller than the public conversation realizes but far stickier than people assume — a 1990s AS/400 installation often outlives three rounds of "we are migrating off the AS/400" project plans.

**OpenVMS** is DEC's 1977 platform — designed by a team that included Dave Cutler before he went to Microsoft and became the lead architect of Windows NT. The lineage went VAX → Alpha → Itanium, and after HP let the product wither, **VMS Software, Inc. (VSI)** acquired the rights in 2014 and is actively porting OpenVMS to x86-64 (V9.x releases since 2020). OpenVMS production deployments concentrate in defense, telecom switching, nuclear utilities, semiconductor fabs, and certain financial back-office shops. Footprint is smaller than IBM Z or IBM i but operationally distinct enough to warrant its own treatment.

**COBOL** is the language-level thread. COBOL applications run across all three substrates above, plus modernized hybrids (COBOL-to-Java translation, COBOL-as-microservice front-ends). Public estimates put production COBOL line counts somewhere between 200 and 800 billion — vendor-supplied numbers from Micro Focus, IBM, COBOL Cowboys, and others, ranging widely depending on what counts as "active." There is no independent census. What's not in dispute: the language remains structurally important, and the workforce that maintains it is aging out faster than it is being replaced.

This document covers all four threads. Each section flags scope honestly: where the 2024-2026 public corpus is thin, where the research community is one or two people deep, and where the vendor-NDA fog is thickest.

---

## 2. Why this document exists

Three structural reasons.

**Workload scale, not workload count.** Mainframe and IBM i installations are not the most numerous computers in any enterprise — they are the most consequential. The ATM transaction, the wire transfer, the insurance claim adjudication, the airline reservation, the Medicaid eligibility check, the unemployment-insurance disbursement, the corporate-tax filing — these workloads do not run on Kubernetes. A breach that compromises the CICS region or the RACF database is categorically different from a breach that compromises a marketing intranet, and the dollar-volume difference can be five orders of magnitude.

**Skills gap as a single-point-of-failure for the broader industry.** The named mainframe-security research community is roughly a dozen people who are public. Phil Young (Soldier of Fortran), Stu Henderson, Mark Wilson (RSM Partners / RSM-affiliated researcher and integrity-bug discoverer), Chad Rikansrud (Bigendian Smalls; DEF CON 23 co-presenter with Phil Young), Ayoub Elaassal (CICS and z/OS privilege-escalation work), Cheryl Watson (z/OS performance and a recurring voice in the security-tangent community). The IBM i community is smaller still — HelpSystems (now Fortra), some of the work that comes out of the COMMON user group, and the always-thin set of independent researchers who present at IBM Power Systems conferences. OpenVMS has even fewer named public researchers post-VSI acquisition. Most security teams have zero in-house competence on any of these substrates. That is itself a security problem at industry scale: the defenders' knowledge is concentrated in a handful of consultants, the offensive research community is concentrated in roughly the same handful of names, and any of them retiring or going dark would meaningfully reduce the world's ability to reason about these systems.

**The 2024-2026 attack surface is real and not entirely public.** More recently, MOVEit-class supply-chain compromises in 2023-2024 hit mainframe-adjacent file-transfer systems. SHARE and GSE conferences (Europe's mainframe user group) document a small but ongoing CVE corpus, and IBM-proprietary APAR numbering captures integrity bugs that never get CVE-assigned. This document accepts that thinness as a working condition and is honest about it.

---

## 3. z/OS attack surface enumeration

z/OS is not Linux with mainframe paint. The execution model, the storage model, the process model, the security model are all different in ways that matter for attack reasoning. The atomic concepts:

**Address spaces.** The closest analog to a Linux process is an *address space*, identified by an ASID. Each address space has its own 16-EB virtual memory map. The system has standard address spaces (MASTER, JES2/JES3, RACF, OMVS for USS, dozens of subsystems) and user address spaces (one per logged-on TSO user, one per started task, one per batch job). Many subsystems run as system address spaces with attributes (e.g., the RACF address space) that grant them latitude unavailable to ordinary code.

**Tasks (TCBs).** Within an address space, the unit of dispatching is a *task*, represented by a Task Control Block. The most-dispatched task is the *primary*, and tasks have parent/child relationships within an address space. The TCB structure is well-documented and a recurring object of low-level integrity research.

**Common Storage.** Memory regions shared across address spaces. The classics: CSA (Common Storage Area), ECSA (Extended Common Storage Area), SQA / ESQA (System Queue Area / Extended). Code or data planted in common storage by an APF-authorized program is visible to every address space and is a load-bearing primitive in many integrity bugs. Modifications to control blocks in common storage are how persistence is achieved at the OS layer.

**PSW (Program Status Word) supervisor-vs-problem state.** Bit 15 of the PSW determines whether the dispatched code runs in *supervisor state* (executing privileged instructions, modifying any storage) or *problem state* (restricted to non-privileged instructions, storage protected by storage keys). Transitions between states are the central security control at the hardware layer. SVC (Supervisor Call) instructions are the syscall analog — but there are also PC (Program Call) and SSAR (Set Secondary ASN) routes that more sophisticated integrity research targets.

**Storage keys.** Each 4-KB page of real storage has a 4-bit key (0-15). The PSW's storage key determines what a program can access. Key 0 storage is the supervisor's; keys 1-7 are reserved for specific system functions; keys 8-15 are general user keys. Mismatched keys cause a 0C4 protection exception. APF-authorized programs can issue `MODESET KEY=ZERO` to switch into key 0 and modify supervisor data; non-APF code attempting this faults.

**Subsystems.** The "applications" of z/OS — JES2, CICS, IMS, DB2, MQ, IRRDBU00, RACF itself, TSO, RRSF — run as subsystems with documented interfaces (SSI = Subsystem Interface). Each subsystem has its own auth model that overlays RACF.

With those primitives in mind, the attack surface enumeration:

### JES2 / JES3 (Job Entry Subsystem)

The job-submission, job-spool, and output-distribution layer. JES2 is the more common variant; JES3 has different internals and a smaller install base. JES is network-accessible in three ways: NJE (Network Job Entry), FTP file-uploads-as-JCL submission, and TN3270/TSO submission. NJE was originally an SNA protocol; it now also runs over TCP/IP. JES2 trust is configuration-based, not cryptographically attested — connections are authenticated by source-node name + password (and TLS in modern configurations, but TLS is opt-in not default).

### TSO/ISPF (interactive subsystem)

The Time Sharing Option is the interactive shell of z/OS, and ISPF (Interactive System Productivity Facility) is the panel-driven editing-and-utility layer most operators live in. TSO commands and ISPF panels drive REXX execs, CLISTs (the older command-list language), and ISPF dialog functions. Attack-relevant primitives: REXX `INTERPRET` (eval), the PARSE statement (string parsing with implicit substring extraction), TBSARG / TBADD ISPF table manipulation, EXECIO (read/write to datasets), and the `OUTTRAP` REXX function for capturing command output. None of these are exploitable in isolation; all of them are common building blocks in homegrown TSO automation that gets misused.

### CICS (Customer Information Control System)

The transaction processing monitor. CICS is what answers when an ATM asks the mainframe a question. The execution model is *pseudo-conversational*: each user interaction is a separate transaction, and persistent state lives in TWA (Transaction Work Area), TSQs (Temporary Storage Queues), and the recoverable CSA-equivalent. Configuration interfaces are CEMT (CICS Master Terminal), CEDA (CICS resource definition online), CEDF (Execution Diagnostic Facility — interactive debugger). Programmatic access via EXEC CICS API calls.

### IMS (Information Management System)

Hierarchical database + transaction monitor; IBM's pre-relational data layer that never went away. IMS DB stores hierarchical data via PCBs (Program Control Blocks) and PSBs (Program Specification Blocks). IMS DC (Data Communications) is the transaction monitor. IMS Connect is the TCP/IP front-end. Smaller install base than CICS, larger when measured by transaction volume per installation.

### DB2 for z/OS

The relational database. Distinct from DB2 LUW (Linux, UNIX, Windows) — same brand, different implementation. SQL injection still applies, with z/OS-specific surfaces around RACF integration (DSNR class controls subsystem access by environment), DSNX@XAC authorization exits, BSDS (Bootstrap Data Set) protection, stored procedures (often written in COBOL, PL/I, REXX, or Java), and DRDA (Distributed Relational Database Architecture) for distributed access.

### WebSphere Application Server for z/OS

Java EE app server on the mainframe. The Java threat model applies (see `java_footguns_expertise.md`), with z/OS-specific surfaces in JCA connectors (CICS / IMS / DB2 connectors), thread isolation across SRB (Service Request Block) dispatching, and the Liberty profile + traditional WAS distinction. The most common modern attack surface — JNDI, deserialization, log4shell-class — applies unmodified.

### z/OSMF (z/OS Management Facility)

REST API + browser UI for z/OS management, introduced around z/OS 1.11 (2009) and steadily expanded. z/OSMF is implemented as a Liberty-profile WebSphere instance. Has had its own CVE corpus over the last decade (authentication and authorization issues that read as standard web-app CVEs but with z/OS-specific privilege impact). The 2024-2026 IBM advisory feed continues to produce z/OSMF CVEs roughly quarterly — `[unverified specific advisory]`: do not cite a CVE number without checking IBM's current Security Bulletins.

### Communications Server

The TCP/IP and SNA stack on z/OS. Telnet 3270 (TN3270), FTP, SFTP, SSH (via OpenSSH on USS), HTTP, SNMP, SMTP — the standard surface. TN3270 in particular has a long CVE history; FTP on z/OS has its own quirks (the file-upload-to-internal-reader vector below).

### Unix System Services (USS)

POSIX layer on z/OS. The bridge between mainframe-native and Unix-native attack surfaces. Discussed in detail in §9.

---

## 4. z/OS auth — RACF, ACF2, Top Secret

z/OS does not have a single auth product the way Linux has PAM-and-/etc/passwd. It has three external security manager (ESM) products in the field. Most installations run one of them. The market is **RACF (IBM, around 60-70% share)**, **ACF2 (Broadcom, formerly CA, formerly SKK)**, and **Top Secret (Broadcom, formerly CA)**.

### RACF — Resource Access Control Facility

IBM's ESM. The model is profile-based:

- **USER profile** — one per identity. Contains password, default group, attributes (SPECIAL, OPERATIONS, AUDITOR), segments (TSO, OMVS for USS UID/GID, CICS, NETVIEW, DCE, KERB, LANGUAGE, etc.). Created with `ADDUSER`, modified with `ALTUSER`, listed with `LISTUSER`.
- **GROUP profile** — collection of users; users are CONNECTed to GROUPs. Group has its own attributes, owner, superior group. Created with `ADDGROUP`, joined with `CONNECT`.
- **DATASET profile** — covers a dataset name pattern (e.g., `PROD.PAYROLL.**`). Has UACC (Universal Access — what everyone gets by default), access list (specific users/groups with PERMIT'd levels), and audit settings.
- **GENERAL RESOURCE profile** — covers anything that isn't a dataset: CICS transactions (TCICSTRN class), DB2 subsystem access (DSNR class), program-class resources (PROGRAM class), surrogate-identity (SURROGAT class), USS resources (UNIXPRIV class, BPX.* facility classes), JES resources (JESINPUT, JESSPOOL, JESJOBS), and dozens of others — each ESM-managed subsystem registers one or more classes.

Sample RACF commands a researcher should read fluently:

```
ADDUSER  WEBAPP01 DFLTGRP(APPGRP1) PASSWORD(redacted) NAME('App Service Acct')
ALTUSER  WEBAPP01 SPECIAL                                    /* DO NOT DO */
CONNECT  WEBAPP01 GROUP(SYSPROG)
RDEFINE  DATASET 'PROD.PAYROLL.**' UACC(NONE) OWNER(PAYOPS)
PERMIT   'PROD.PAYROLL.**' ID(PAYROLE) ACCESS(READ)
PERMIT   'PROD.PAYROLL.**' ID(PAYOPS)  ACCESS(ALTER)
SETROPTS CLASSACT(TCICSTRN)
RDEFINE  TCICSTRN CEMT UACC(NONE)
PERMIT   CEMT CLASS(TCICSTRN) ID(CICSADM) ACCESS(READ)
SETROPTS RACLIST(TCICSTRN) REFRESH
LISTUSER WEBAPP01
LISTDSD  DA('PROD.PAYROLL.**') ALL
```

**Known weaknesses and recurring misconfigurations** (every named item below appears in multiple Phil Young / Stu Henderson / Mark Wilson talks across the 2013-2023 window — they are not novel, they are the workhorses):

- **SPECIAL attribute creep.** SPECIAL on a USER profile grants RACF administrative power — equivalent to root. OPERATIONS grants access to all datasets (bypassing the dataset access lists). The combination is *de facto* domain admin. Both are over-granted at almost every installation that has ever been audited. SPECIAL on a group (group-SPECIAL) is the same authority scoped to the group's resources but is just as dangerous when the group's scope is broad.
- **WARNING mode resources.** A RACF profile with WARNING set logs violations but allows access. Intended as a temporary measure during onboarding; ends up permanent in many shops. A WARNING-mode resource is functionally unprotected.
- **APF library protection.** Programs in datasets on the APF list can transition to supervisor state. Write access to any APF library is an integrity-equivalent privilege escalation primitive. UACC=UPDATE or UACC=ALTER on an APF library is a misconfiguration that immediately yields supervisor state to anyone who can run a job. Section 6 expands on this.
- **SURROGAT class.** Allows one user to submit jobs that run as another user. The classic auth-delegation surface and a classic privilege-escalation primitive when over-granted. `RDEFINE SURROGAT WEBAPP01.SUBMIT UACC(NONE)` + `PERMIT WEBAPP01.SUBMIT CLASS(SURROGAT) ID(PROD-BATCH-SCHEDULER) ACCESS(READ)` is the right shape; a careless `UACC(READ)` opens the surrogate to everyone.
- **PROGRAM class.** Controls which programs may execute (program-pathing). Semantics are subtle — combined with PADS (Program Access to Data Sets) and conditional access, it's one of the more complex parts of RACF and the part most often bypassed. PADS lets a program access data only while executing — a clean idea that frequently breaks down to "PADS is disabled because someone needed to debug it once."
- **UACC=READ/UPDATE/ALTER on dataset profiles.** Direct ACL misconfiguration; the mainframe equivalent of an S3 bucket open to the world. Common on legacy "everyone needs to read this" datasets that nobody reviewed.
- **OPERAUDIT not enabled.** SETROPTS OPERAUDIT records SPECIAL and OPERATIONS user activity in SMF. Off by default-ish (depending on RACF version and OPTIONS-data setup); off in many shops. Without OPERAUDIT, a compromised SPECIAL user leaves a much thinner audit trail.
- **IRR.* class profiles.** RACF protects its own administrative interfaces via IRR.* profiles in the FACILITY class (IRR.PASSWORD.RESET, IRR.LISTUSER, etc.). Most installations protect a few of these and forget the rest, leaving inquiry interfaces wide open.
- **Database integrity.** The RACF database is a single-extent dataset (classically non-VSAM, physical sequential). Backup copies on tape or unprotected DASD are functionally credential dumps — every password hash, every group membership, every ACL.

### ACF2 (Broadcom)

The model is fundamentally different from RACF — rule-based rather than profile-based, deny-by-default at a finer granularity. Identities are *LIDs* (Logonid records). Authorization is expressed as access rules and resource rules:

```
$KEY(PROD.PAYROLL.-)
- UID(*) READ(L)         /* default: log */
PAYROLE UID(*) READ(A)   /* PAYROLE LIDs: allow read */
PAYOPS  UID(*) ALLOW     /* PAYOPS LIDs: full access */
```

ACF2 was historically marketed as more secure-by-default than RACF (the defaults bite differently — ACF2 will deny things RACF would have allowed). In practice, the security properties of an ACF2 shop versus a RACF shop are driven entirely by the operations team running it, not the product. Both products can be locked down hard; both products can be configured into hot garbage.

### Top Secret (Broadcom)

The third ESM. Departmental / divisional / profile hierarchical model — ACIDs (Accessor IDs) are organized into divisions and departments, with permissions inherited down. Less common than RACF or ACF2 but still in the field, particularly at older shops that picked it in the 1980s and never converted.

### Honest scope note

This document does not equip a reader to do a clean-room RACF audit from cold start. The RACF Auditor's Guide, RACF Administrator's Guide, and Mark Wilson's "RACF on Z/OS" GSE materials are the operational references. What this section establishes is the *threat-model shape* — that z/OS authorization is a closed-world, single-organization model fundamentally unlike the distributed AuthZ universe (see `[[reference-distributed-authz]]` for that contrast) — and the names of the common misconfigurations to look for first.

---

## 5. JES2 / NJE attack surface

The Job Entry Subsystem is mainframe-specific and deserves its own section because it has its own protocol, its own trust model, and its own well-developed offensive research corpus.

### Job submission via FTP

z/OS FTP supports uploading data to the *internal reader* (INTRDR), which submits the uploaded content as JCL. Default RACF protection on the JESJOBS class controls who may SUBMIT JCL — but it is class-default-permit in default installations, and the FTP user's RACF identity must explicitly lack SUBMIT access to be blocked. The result: any user with valid FTP credentials may submit arbitrary JCL unless explicitly denied.

```
ftp> quote site filetype=jes
ftp> put exploit.jcl
```

`exploit.jcl` is plain JCL. It runs under the FTP user's RACF identity. If the FTP user is over-privileged — which is common for "service account" identities that accumulate access over years — this becomes arbitrary code execution as that identity.

### TN3270 + TSO

The 3270 terminal protocol is the original mainframe interactive front-end. TN3270 (Telnet 3270 over TCP) is the IP version. Most installations run both TN3270 (plaintext) on port 23 and TN3270 + TLS on port 992 — and the plaintext port is almost always still accessible inside the corporate network because some emulator on some operator's desk has not been upgraded since the Clinton administration. Credential capture on the wire is straightforward; once authenticated, the attacker has TSO and can run any TSO command, REXX exec, or submit JCL.

### NJE — Network Job Entry

The jewel of this section and the subject of Phil Young's most-cited work.

NJE is the protocol by which mainframes exchange jobs and SYSOUT with each other. Originally an SNA RSCS protocol from the VM/RSCS era; modern z/OS supports NJE over TCP/IP. Two mainframes that share an NJE link can submit jobs to each other, retrieve output, send messages to operators, and exchange spool data.

The trust model: NJE links are defined in JES2/JES3 configuration with a peer node name and a node-pair password. Once the link is up, JES treats jobs arriving from the trusted peer as if they came from local users with the credentials embedded in the job card. There is no cryptographic attestation of peer identity beyond the static configuration password (modern z/OS does support TLS for NJE, but adoption is slow). The trust is therefore configuration-based and is exactly as strong as the discipline around the node-pair password.

**Phil Young's NJE attacks** (DEF CON 23, 2015, "Security Necromancy: Further Adventures in Mainframe Hacking", with Chad Rikansrud; PoC||GTFO 12:6): demonstrated that an attacker who can either (a) plant themselves on the network path of an NJE link, (b) compromise a node that is already trusted, or (c) discover or brute-force the node-pair password can submit jobs to the target mainframe that execute with the privilege of the attacker's choice of impersonated user. The impersonated user's identity is determined by the USER= parameter on the job card; if the target's RACF does not enforce strict node-of-origin propagation, USER=anything is honored.

The defense is straightforward in principle:
- RACF NODES class — define profiles in the NODES class that constrain which userIDs can be impersonated from which nodes. Without NODES class enforcement, NJE trust is transitive and unbounded.
- Disable plaintext NJE; require TLS.
- Audit the node-pair password rotation cadence (it's almost certainly never been rotated).

In practice, the NJE configurations in production are old, inherited, and often connect mainframes in ways that nobody on the current team understands or documents.

### z/OS Communications Server CVE history

The TN3270 server, FTP server, and underlying Communications Server have produced CVEs intermittently for years. A representative class — `[unverified specific advisory]`: I won't quote specific CVE numbers from memory, and IBM's quarterly Security Bulletin is the authoritative source — but the recurring bug classes include buffer-overflow / heap-corruption issues in FTP control-channel parsing, authentication-bypass issues in TN3270 cipher negotiation, and integer-overflow in SMB / NFS adjacent services that ship as part of Communications Server. The pattern matches what one would expect from C code maintained continuously for forty years.

---

## 6. APF authorization and supervisor-state escalation

The Authorized Program Facility is the structural pivot of z/OS integrity. Every serious z/OS security conversation reduces, sooner or later, to APF.

### What APF is

z/OS maintains a list of datasets — the *APF list* — whose programs are eligible to transition from problem state into supervisor state and into key zero. The list is populated by IPL parameter (PROGxx member of PARMLIB), by the SETPROG APF dynamic command at runtime, or implicitly by the linklist concatenation under certain rules.

A program in an APF-authorized library, link-edited with the `AC=1` attribute, may issue instructions that switch storage key (MODESET KEY=ZERO) and switch state (MODESET MODE=SUP). With those two capabilities, the program can modify any storage anywhere in any address space, including the supervisor's own control blocks. In Linux terms: APF is the combined equivalent of setuid-root, kernel module load, and writing to /dev/kmem.

The conceptual analog to "kernel mode" is *supervisor state with PSW key 0*, which is what APF programs can switch into. Without APF, no program (no matter how lucky) reaches supervisor state via documented interfaces. A bug that lets a non-APF problem-state program reach supervisor state is — by IBM's contractual definition — an *integrity exposure*, and IBM commits to ship a fix via APAR.

### Why APF matters operationally

APF abuse path:
1. Identify the APF list. Anyone can read PROGxx in PARMLIB (assuming default RACF on PARMLIB datasets, which is typical) or run `D PROG,APF` from console / SDSF if they have console authority.
2. Find an APF library with write access. Common candidates: ISV product libraries (vendor X's product, installed in 2007, last patched in 2012, owned by a team that no longer exists), homegrown utility libraries that were APF-authorized "temporarily" a decade ago, libraries shared across multiple LPARs in a sysplex where ownership is ambiguous.
3. Link-edit a small program with `AC=1`, copy it into the writable APF library.
4. Run the program. It now executes with the right to switch into supervisor state and key zero.

Once in supervisor state key zero, the program can:
- Modify the RACF database in memory to grant SPECIAL.
- Plant code in CSA/ECSA that runs in every subsequent dispatch.
- Bypass any application-layer or RACF-layer control.
- Cover its tracks in SMF by manipulating the SMF buffers before they're written.

### The integrity statement

IBM's *System Integrity Statement* (originally issued in 1973 for MVS, restated for every subsequent z/OS release) is the contractual promise that supervisor state cannot be reached from problem state without going through APF — i.e., without explicit installation-side authorization. Bugs that violate this promise are *integrity exposures*. IBM commits to fix them under APAR, often in security-only PTFs distributed under proprietary channels. Many integrity bugs never receive a CVE because the IBM disclosure process predates and parallels MITRE's CVE assignment.

**Mark Wilson** (RSM Partners, GSE conferences 2013-2022) is the most consistently public researcher in this area. His talks document the rate of integrity APARs (roughly several per quarter for active z/OS releases), the recurring classes of integrity bugs (uninitialized parameter validation in SVCs, race conditions in cross-memory services, missing authorization checks in PC routines), and the structural reason these bugs persist: the z/OS codebase is enormous, the privileged-code subset is large, and the engineering discipline that catches integrity bugs (rigorous parameter validation on every entry point from problem state) is hard to maintain consistently across decades of incremental change.

**Phil Young's** complementary work demonstrated *exploitation* of APF-class primitives in the public domain — proof-of-concept code at BSidesLV showing supervisor-state escalation through documented misconfigurations rather than zero-day integrity bugs. The lesson is that the misconfigured-APF-list problem is the working attack vector at most installations long before the zero-day integrity bug is.

### Defending APF

- **Audit the APF list.** Pull `D PROG,APF` output. Cross-reference every entry against current ownership. Remove anything you cannot map to an active owner and an active product.
- **Audit access to every APF library.** UACC should be NONE; explicit access list should be the minimum required for the product's operational team. Write access by anyone outside that team is a finding.
- **Audit AC=1 modules.** Within each APF library, individual modules are link-edited with or without AC=1. The set of AC=1 modules is the actual attack surface; the rest of the library matters mostly because of write-access propagation. AMBLIST (LISTLOAD) reports load-module attributes.
- **Restrict SETPROG APF.** Dynamic addition to the APF list (via SETPROG console command) must be restricted via RACF (FACILITY class CSVAPF.* profiles in recent z/OS). Otherwise an attacker with console authority can transiently APF-authorize a library they control.
- **Apply integrity PTFs aggressively.** Integrity exposures are not optional. The fact that they shipped under proprietary numbering does not change the threat model.

---

## 7. DB2 for z/OS specifics

DB2 for z/OS is structurally distinct from DB2 LUW. SQL injection still applies. The DB2-specific surfaces:

### RACF integration via the DSNR class and access control module

DB2 plans and packages — the compiled representation of an application's SQL — can be gatekept by RACF profiles through the RACF access control module at the DSNX@XAC exit; the DSNR class controls which users may connect to a DB2 subsystem from each environment (BATCH, CICS, IMS, DIST, RRSAF). A user must hold the right plan-execution authority to run a transaction. Default protection is generally tight; the failure mode is over-permission rather than under-permission, with PERMIT lists growing over years as one team after another needs access for a project nobody documented.

### DSNX@XAC authorization exits

DB2 supports site-customizable authorization exits. The most common is DSNX@XAC, which is invoked on every authorization check. The intent is to integrate DB2 authorization with site-specific policy beyond RACF. The risk: a compromised or maliciously-modified DSNX@XAC short-circuits every DB2 authorization decision. Auditing this exit module's contents and load path is a one-line answer to many questions about whether DB2 authorization is actually being enforced.

### BSDS (Bootstrap Data Set)

DB2's configuration — log placement, image-copy registry, archive log inventory — lives in the BSDS, a VSAM dataset. The BSDS must be RACF-protected at the same level as the most sensitive data DB2 contains. A read of the BSDS reveals enough about the DB2 subsystem layout to plan further attacks; a write to the BSDS (via APF abuse or via a misconfigured access list) can corrupt the DB2 catalog or redirect log writes.

### Stored procedures and UDFs

DB2 for z/OS supports stored procedures in COBOL, PL/I, REXX, C, Java, and native SQL. UDFs (User-Defined Functions) similarly. A stored procedure or UDF executes in its own WLM-managed address space, with its own RACF identity. The privilege model gets subtle: the calling user's identity vs. the stored procedure's identity (DEFINER vs. INVOKER, in modern DB2). Misconfiguration patterns mirror Oracle/PostgreSQL DEFINER-rights pitfalls — a stored procedure that runs as a privileged identity but takes user-controlled SQL input is an immediate horizontal privilege escalation surface.

### DRDA (Distributed Relational Database Architecture)

DB2 Connect speaks DRDA to z/OS DB2 from distributed clients. DRDA supports TLS (DB2 Connect's `SECURITY=SSL`), but legacy configurations ship plaintext credentials over port 446 / variants. Network-layer interception is direct credential capture.

SQL-dialect-specific footguns for DB2 for z/OS (procedural extensions, edge cases in numeric coercion, dynamic SQL via PREPARE / EXECUTE) deserve their own treatment; the cross-language SQL footgun document at `sql_dialect_footguns_expertise.md` does not currently include DB2 for z/OS as a first-class dialect. Worth a future deepening.

---

## 8. CICS and IMS specifics

### CICS

The transaction processing monitor. Conceptually CICS is a small operating system within an operating system: it has its own dispatcher, its own storage manager, its own resource definitions, its own programming API.

**Resource model.**
- **TRANSID** — a 4-character identifier the user enters on the 3270 screen to start a transaction (`CESN` to sign on, `CEMT` to invoke the master terminal, `CEDA` to define resources, application TRANSIDs are typically site-specific 4-letter names).
- **PCT (Program Control Table)** — maps TRANSID to a PROGRAM name. Modern CICS uses CSD (CICS System Definition) instead of an actual table, but the concept persists.
- **PPT (Processing Program Table)** — maps PROGRAM to a load module.

The implication for backdoor injection: an attacker who can modify PCT/PPT (i.e., issue `CEDA DEFINE TRANSACTION(EVIL) PROGRAM(EVIL)` and `CEDA DEFINE PROGRAM(EVIL) LANG(COBOL)`, then install it) creates a TRANSID that anyone with the privilege to invoke it can run, executing arbitrary code in the CICS region. The CICS region itself runs with a RACF identity (often a privileged one) and access to the full set of resources the region is authorized for.

**Configuration interfaces.**
- **CEMT** — CICS Master Terminal. Inquire and modify the state of any resource in the region (`CEMT I PROGRAM(*)`, `CEMT P SYS`).
- **CEDA** — CICS resource definition. Add/modify TRANSACTION, PROGRAM, FILE, etc., definitions.
- **CEDF** — Execution Diagnostic Facility. Interactive debugger; allows stepping through a transaction. CEDF in production is a credential-equivalent privilege — the debugger can modify in-flight data.

All three live in the TCICSTRN class in RACF (and CCICSCMD in modern configurations). PERMIT access to these transactions to anyone outside the CICS operations team is a finding.

**CICS Web Services / REST.**
Modern CICS exposes web-services interfaces via CICS Web Support, the Liberty profile embedded in CICS (CICS TS 5.x and later), and CICS bundle deployment. These expose CICS transactions to HTTP / SOAP / REST clients. The auth surface adds SAML, OAuth, Basic auth, mTLS, and WS-Security on top of RACF — and getting the interaction right between web-layer auth and CICS-layer auth is consistently the hardest configuration to get correct. Common misconfiguration: an HTTP endpoint exposed without authentication that invokes a high-privilege TRANSID, often because the URI mapping was set up in development with "we'll fix the auth later" and was never fixed.

### IMS

The hierarchical database and transaction monitor. Smaller install base than CICS but transactional volume per installation can be enormous — IMS still runs the back end of many of the world's largest airlines and several large banks.

**Model.**
- **PSB (Program Specification Block)** — defines the views (PCBs) a program may access. The unit of database authorization.
- **PCB (Program Control Block)** — a view into one IMS DB hierarchy or a logical terminal for DC.
- **DBD (Database Description)** — the schema of a database.

**Attack surfaces.**
- **IMS Connect** — TCP/IP front end for IMS DC. Listens on a port, accepts OTMA messages, dispatches to IMS transactions. Authentication is RACF-based but the integration is via the IMS Connect user exit, which (like DSNX@XAC for DB2) is a single point of trust for the entire stack.
- **/SECURE APPC / /SECURE OTMA** — the IMS command that sets the RACF security level (NONE, CHECK, FULL, PROFILE) for APPC and OTMA input.
- **Master terminal commands** (the IMS analog of CEMT) — high-privilege configuration commands that an attacker on the master terminal can execute.

IMS receives less public security research attention than CICS, in part because the install base is smaller and in part because IMS's documentation curve is steeper.

---

## 9. Unix System Services (USS) bridges

USS is the POSIX layer on z/OS. It exposes a Unix-style filesystem rooted at `/`, supports fork/exec, runs OpenSSH, runs Apache, runs Java, runs every Unix-style daemon that has been ported. It is the most modern-looking part of z/OS and, for that reason, the part most likely to be misconfigured by Unix-trained admins who assume Unix mental models apply.

### Identity bridging

A USS user is a RACF identity with an OMVS segment. The OMVS segment provides the UID, GID, home directory, and login shell. Two RACF identities with the same UID are functionally the same Unix user — accidentally creating two RACF users with UID=0 (root) is a classic foot-shooting pattern.

```
ADDUSER  ALICE OMVS(UID(1001) HOME('/u/alice') PROGRAM('/bin/sh'))
ALTUSER  ALICE OMVS(UID(0))    /* DO NOT DO */
```

UID 0 in USS is root. A USS process running as UID 0 has the full set of Unix root privileges within the USS subsystem, including the ability to issue setuid system calls.

### File permissions and UNIXPRIV

Files in the USS filesystem have Unix chmod permission bits (`rwx` for owner, group, other) AND can be governed by RACF profiles in the UNIXPRIV class. The two systems compose:
- **UNIXPRIV** lets RACF grant Unix privileges to users without making them UID 0. E.g., SUPERUSER.FILESYS lets a non-root user read any file; CHOWN.UNRESTRICTED lets a user change ownership of files they own to arbitrary other users (a setuid-class privilege).
- **chmod bits** apply on top.

Misconfiguration patterns:
- World-writable directories on critical paths (`/etc`, `/var/tmp`, `/opt/vendor`) — the classic Unix pitfall with the classic Unix consequence.
- FACILITY-class BPX.SUPERUSER granted to many users — flatly equivalent to root for those users, often granted in shops where "we have a lot of Unix admins and they all need root."

### APF authorization in the USS context

USS executable files have an *extattr* attribute. Files with `extattr +a` (APF-authorized) and `extattr +p` (program-controlled) get special handling. An `extattr +a` program in USS is the equivalent of an APF-authorized program in MVS — it can transition to supervisor state. The same APF threat model applies in USS, with the additional surface area that USS file ownership and permission semantics interact with extattr in non-obvious ways.

### OpenSSH on z/OS

z/OS ships OpenSSH. Configuration patterns mirror Linux OpenSSH — `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, the same set of options. Misconfiguration patterns mirror Linux: `PermitRootLogin yes`, weak ciphers, password authentication enabled, no key rotation. The Unix-side OpenSSH expertise applies essentially unmodified — and the operations team running OpenSSH on z/OS often is not the operations team running RACF, which introduces an inter-team-gap class of misconfigurations where SSH access bypasses RACF expectations.

### Shell injection in USS

USS shell scripts and shells-invoked-from-COBOL-via-BPXBATCH have the standard shell-injection failure modes (see `[[reference-shell-injection]]`). The COBOL → shell bridge is particularly fragile — a COBOL program that constructs a shell command by string concatenation from user input has the same shell-injection consequence as the equivalent Python or Node.js code.

```
01 SHELL-CMD PIC X(256).
   STRING 'sh -c "' DELIMITED BY SIZE
          USER-INPUT-FIELD DELIMITED BY SIZE
          '"' DELIMITED BY SIZE
   INTO SHELL-CMD
   CALL 'BPXWUNIX' USING SHELL-CMD
```

USER-INPUT-FIELD reaches the shell. Same bug as everywhere else.

---

## 10. IBM i (AS/400) attack surface

IBM i is the smaller of the IBM Power-mainframe-adjacent platforms in the public conversation but the more numerous in actual installation count. Banks, insurance carriers, manufacturers, distributors, healthcare back-office — anyone who bought a System/38 in 1980 or an AS/400 in 1990 and never migrated is running IBM i in 2026. The architecture has structural properties that affect threat modeling:

### Single-level storage

IBM i does not distinguish between RAM and disk to programs — the entire address space is virtual, backed by storage that may be in memory or on disk transparently to the program. This is not a security primitive directly, but it means traditional Unix mental models around "in-memory vs. on-disk" do not apply.

### Object-based architecture

Everything is an *object* — files, programs, libraries, queues, profiles, devices — and every object has a *type* (`*FILE`, `*PGM`, `*LIB`, `*USRPRF`, `*JOBQ`, `*DEVD`, etc.) that determines what operations are valid. Objects have an *owner*, an *authorization list* (a named ACL that can be shared across objects), and *public authority* (the equivalent of UACC).

### Authorities

The object authorities in IBM i are:
- **Object operational authorities**: `*OBJOPR`, `*OBJMGT`, `*OBJEXIST`, `*OBJALTER`, `*OBJREF`.
- **Data authorities**: `*READ`, `*ADD`, `*UPD`, `*DLT`, `*EXECUTE`.
- Aggregates: `*USE` (objopr + read + execute), `*CHANGE` (use + add/upd/dlt), `*ALL` (everything).
- `*EXCLUDE` denies.
- `*AUTL` indicates "see the authorization list."

`*PUBLIC` is the default authority for any user not on the explicit auth list — the AS/400 UACC equivalent.

### Special authorities

The blast-radius authorities:
- **\*ALLOBJ** — root-equivalent. Grants access to every object on the system. Should be on the chairman of the board, the CIO, and approximately three operations engineers; in practice is on dozens of identities at most installations.
- **\*SECADM** — security administrator. Can create and modify user profiles.
- **\*SAVSYS** — save the system; can read every object regardless of authority.
- **\*JOBCTL** — control jobs; can manipulate the job queue and subsystem.
- **\*SPLCTL** — spool control; can read any spool file regardless of authority.
- **\*SERVICE** — perform service functions; deep system access.
- **\*AUDIT** — change audit configuration.
- **\*IOSYSCFG** — configure I/O, communications, networking.

`*ALLOBJ` creep mirrors RACF SPECIAL creep. The same dynamic — every new system, every vendor product, every emergency-during-go-live justifies one more `*ALLOBJ` grant, none of which are ever rescinded.

### System values

System-wide configuration. The security-relevant ones:
- **QSECURITY** — system security level. Values: 20 (password security; objects unprotected), 30 (resource security), 40 (operating system integrity), 50 (extended OS integrity, the modern recommended baseline). **QSECURITY=20 is still in production** at some sites — a finding equivalent to "the firewall is off."
- **QAUDLVL / QAUDLVL2** — what gets audited. If these are minimal, the audit trail is minimal.
- **QRMTSIGN** — controls remote sign-on behavior. `*VERIFY` allows sign-on bypass even when source and target profiles differ; `*SAMEPRF` allows bypass when source and target have the same profile; `*FRCSIGNON` always requires sign-on.
- **QMAXSIGN** — maximum incorrect sign-on attempts before profile is disabled.
- **QPWDLVL** — password level. Values 0/1 allow short DES-hashed passwords; 2/3 enable long passwords with SHA-1 hashing; 4 (more recent) enables PBKDF2. Many shops still run at level 2.

### Access protocols

- **5250 terminal emulator** — the AS/400's native interactive protocol. The IBM i analog of TN3270.
- **Telnet (5250 over IP)** — port 23. Plaintext credentials by default unless TLS-wrapped on port 992.
- **FTP** — same internal-reader-equivalent risk as z/OS (FTP can submit commands via `QUOTE RCMD`).
- **ODBC / JDBC** — DB2 for i database access from external systems.
- **IBM Navigator for i** — web-based management interface. Has its own CVE history (`[unverified specific advisory]`).
- **PASE** — Portable Application Solutions Environment. The Unix layer on IBM i (analogous to USS on z/OS). Runs AIX-style binaries. The Unix-side shell-injection mental model applies.

### Service Tools (DST / SST)

Dedicated Service Tools and System Service Tools — the IBM i maintenance interfaces. Deep access to the IPL process, the LIC (Licensed Internal Code) layer, the disk subsystem. DST is accessed during IPL; SST is accessed from a running system. Default DST credentials (`QSECOFR / QSECOFR`, `22222222 / 22222222`, etc.) historically shipped on every system. Whether they have been changed is a binary question every IBM i auditor asks first.

### Known research community

The IBM i security research community is the smallest of the three substrates covered here. The **COMMON user group** in North America and the **COMMON Europe** organization host conferences with security tracks; the SHARE-equivalent visibility is lower. Recent CVEs in IBM i HTTP Server, IBM Navigator for i, and the IBM i Access Client Solutions clients are documented on IBM's Security Bulletin feed — `[unverified specific advisory]` again; check current bulletins for specifics. IBM i exit programs (registered in the Registration Facility, `WRKREGINF`) are a per-installation customization surface; misconfigured or backdoored exit programs are a recurring finding.

---

## 11. OpenVMS attack surface

OpenVMS is the smallest of the three substrate threads but operationally distinctive. Defense, telecom switching, nuclear utilities, certain financial back-office, semiconductor fabrication tools — niches where OpenVMS's clustering, uptime, and determinism remain competitive.

### Architecture

VMS is a clustered operating system from inception. Multiple nodes (originally VAX, then Alpha, then Itanium, now x86-64) share storage and present as a single system. The cluster is a security boundary — once inside the cluster, you are on every node.

### Identity model

Users are *UAF (User Authorization File)* records. The UAF stores username, password hash, default privileges, allowed login times, and other policy. Authentication is against the UAF or, in modern configurations, against an LDAP/AD via ACME (Authentication and Credentials Management Extension) modules.

### Privileges

OpenVMS has a fine-grained privilege model — more granular than Unix's all-or-nothing root. Per-process privileges include:
- **SETPRV** — set any privilege (the meta-privilege; equivalent to root).
- **SYSPRV** — bypass discretionary access control checks.
- **BYPASS** — bypass all access checks.
- **READALL** — read any file regardless of ACLs.
- **OPER** — operator-class commands.
- **SECURITY** — security-administration functions.
- **CMKRNL** / **CMEXEC** — change mode to kernel / executive (the privilege required to call privileged routines).
- **ALL** — all privileges.

Authorized privileges (what the user *can* enable) and current privileges (what is enabled now) are distinct in VMS — a SET PROCESS/PRIVILEGES command can enable privileges within the authorized set.

`SETPRV` is the keystone. A process with SETPRV can grant itself any other privilege at any time. `BYPASS` skips all DAC checks, which is functionally equivalent to root-via-file-access but does not (by itself) grant kernel mode.

### Protection codes (UIC) and ACLs

The original VMS protection model is *UIC-based*: every file has an owner UIC (User Identification Code, structured as `[group, user]`) and four sets of permissions for SYSTEM / OWNER / GROUP / WORLD. The model is reminiscent of Unix but with four classes instead of three and bidirectional inheritance semantics that occasionally surprise newcomers.

ACLs were added in VMS 4 — finer-grained access control beyond UIC. ACL entries are processed in order; a deny ACE blocks access before the UIC code is consulted. ACL misconfigurations look like Linux POSIX ACL misconfigurations: stale entries, "deny-then-allow" ordering mistakes, ACLs added during one project and never removed.

### DCL — Digital Command Language

DCL is OpenVMS's scripting language. The command-injection failure mode in DCL is structurally identical to bash, with VMS-specific quoting rules:

```
$ ! DCL injection
$ FILENAME = F$TRNLNM("INPUT")
$ TYPE 'FILENAME'           ! single-quote forces symbol substitution
                            ! attacker-controlled FILENAME is injected
                            ! before TYPE parses arguments
```

The `'symbol-name'` (apostrophe-symbol-apostrophe) construct substitutes the symbol's value into the command line before parsing. User input flowing into a symbol that is then expanded with apostrophes is the canonical DCL injection. Defense is identical to shell: validate, quote, never trust user input to construct command lines.

### Known CVE corpus

OpenVMS has produced CVEs intermittently:
- **CVE-2017-17482** — OpenVMS DCL buffer overflow: a malformed DCL command table lets a non-privileged local user with a crafted command line gain higher privileges (VAX/VMS 4.0 and later; exploitable on VAX and Alpha).
- Various TCP/IP Services for OpenVMS CVEs across the 2010-2020 window — SMTP, FTP, finger, lpd services have all produced bugs.
- TCP/IP stack issues from the underlying Multinet / DEC TCP/IP / VSI TCP/IP implementations.

`[unverified specific advisory]`: VSI publishes security alerts on their portal; the public CVE corpus is partial because some HP-era issues were fixed in patches that never received CVE assignments.

### Research community

VSI itself publishes security guidance but is not a research vendor. The OpenVMS security research community is the thinnest of the three substrates; presentations at DECUS-successor events (HP Enterprise Technology Conferences in the HP era; VMS Boot Camp under VSI) carry the line, but the public-facing offensive research output is sparse.

### Operational note

Many OpenVMS deployments are highly air-gapped — defense, nuclear, fab-floor. Air-gap-relative-not-absolute: the network is administered, the operations team has a path in, the vendor has a maintenance access, and any of those is the attack surface. The 2010 Stuxnet lineage demonstrated that "air-gapped" systems have data flows that reach them; assuming OpenVMS installations are unreachable is rarely accurate.

---

## 12. COBOL footguns (language-level)

Cross-link `[[reference-language-footguns-class]]` for the broader per-language unsafe-primitive treatment. COBOL belongs in that class and is treated here.

### Variable-length string handling

COBOL strings are fixed-length by default — `PIC X(N)` declares an N-byte field. Two sources of bugs:

**REDEFINES misalignment.**
```
01 BUFFER PIC X(100).
01 BUFFER-PARSED REDEFINES BUFFER.
   05 HEADER PIC X(10).
   05 BODY   PIC X(80).
   05 CHECKSUM PIC X(10).
```

If a future change extends HEADER to PIC X(12), every field after it shifts. If the file format changes externally, every program reading it begins to read mis-aligned data silently. There is no compile-time check that BUFFER-PARSED's component sizes match BUFFER's total length unless `REDEFINES` is strict — and even then, semantic alignment with the input format is unchecked.

**STRING / UNSTRING / INSPECT.**
```
STRING USER-INPUT DELIMITED BY ' '
       INTO OUTPUT-BUFFER
       WITH POINTER OUT-PTR
       ON OVERFLOW PERFORM HANDLE-OVERFLOW
       END-STRING
```

The `ON OVERFLOW` clause is the bounds check. Omitting it on `STRING` means overflow is silent — the output buffer is filled to capacity and the remaining source data is discarded without notice. The same silent-truncation pattern in `UNSTRING` (without `ON OVERFLOW`) means an attacker-controlled input with unexpected delimiter placement parses into a corrupted state.

### EVALUATE TRUE WHEN — missing WHEN OTHER

COBOL's switch:
```
EVALUATE TRUE
    WHEN TXN-TYPE = 'DEBIT'  PERFORM PROCESS-DEBIT
    WHEN TXN-TYPE = 'CREDIT' PERFORM PROCESS-CREDIT
    WHEN TXN-TYPE = 'INQ'    PERFORM PROCESS-INQUIRY
END-EVALUATE
```

Missing `WHEN OTHER` means an unexpected TXN-TYPE silently falls through with no handler. Subsequent code runs against state that PROCESS-* assumed was set up but wasn't. In transaction processing this can mean "the deposit is recorded but the source account is not debited," a class of bug that has settled real-money disputes.

### CALL "..." USING

Dynamic program calls:
```
01 PROGRAM-TO-CALL PIC X(8) VALUE SPACES.
...
CALL PROGRAM-TO-CALL USING PARM-AREA
```

If `PROGRAM-TO-CALL` is set from user input — directly or indirectly — the attacker chooses which COBOL subprogram to invoke. The set of valid choices is the set of load modules in the program's load library. Combined with LIBPATH manipulation in USS or STEPLIB manipulation in JCL, dynamic CALL becomes a remote code execution primitive.

### Numeric data type confusion

COBOL's COMP-3 (packed decimal) and DISPLAY (zoned decimal) are distinct storage representations of the same conceptual number:
```
01 AMOUNT-DISPLAY PIC 9(7)V99.
01 AMOUNT-COMP3   PIC 9(7)V99 COMP-3.
```

The two declarations occupy different byte counts. REDEFINES across these creates silent corruption. Worse, MOVE between display and computational forms triggers conversion — and the conversion has edge cases (leading-zero handling, sign nibble representation in COMP-3, half-byte boundary alignment) that have produced subtle bugs in banking software for decades.

### Spaghetti complexity

GO TO depth in legacy COBOL is structural: programs of 50,000+ lines with GO TO chains crossing thousands of statements are common. Following the control flow to determine "what is the actual authorization check before this UPDATE statement runs" is the canonical hard problem in COBOL security review. There is no Semgrep equivalent that handles arbitrary GO TO graphs gracefully. Cross-link `[[reference-code-review-expertise]]` for the click-count-severity framework that applies; in COBOL the click count tends to be high.

### Modernization-by-translation anti-patterns

Several vendors (Micro Focus / OpenText, AWS Blu Age, IBM Watson Code Assistant for Z, Mainframe Migration Accelerator) automate COBOL-to-Java translation. The translation is correct on a per-statement basis and frequently incorrect on a per-program basis — the resulting Java code is morphologically COBOL with Java syntax, retaining COBOL's structural assumptions (fixed-length records, implicit padding, sign-nibble semantics) in a language that does not natively support them. Auditing translated code is auditing two languages at once. AI-augmented translation (Watson Code Assistant and contemporary tools) adds the translation-introduced-bug surface discussed in `ai_assisted_coding_tool_security_expertise.md`.

---

## 13. CVE corpus and recent incidents

The mainframe and IBM i CVE corpus is small relative to the install base but consistent.

### z/OS and z/OSMF

IBM publishes Security Bulletins quarterly via the IBM Support portal. The 2023-2025 stream has included z/OSMF authentication and authorization issues, Communications Server FTP and TN3270 bugs, several Java-side issues that affect WebSphere on z/OS, and various integrity APARs that ship under proprietary numbering. **`[unverified specific advisory]`** — I will not cite specific CVE numbers from memory; consult IBM's current Security Bulletins at the time of audit.

Pattern observation across the public corpus:
- Integrity bugs concentrate in SVC and PC routine parameter validation.
- Communications Server bugs concentrate in protocol-parser code paths.
- z/OSMF bugs read as standard web-application CVEs (broken auth, IDOR, XXE) but with z/OS-specific impact because z/OSMF can affect system-level configuration.

### IBM i

Recent IBM i CVEs (2023-2025) include issues in IBM i HTTP Server (Apache-derived), IBM Navigator for i (the web management UI), IBM i Access Client Solutions, and several Db2 for i issues. **`[unverified specific advisory]`**.

### OpenVMS

Documented earlier in §11. The OpenVMS CVE corpus is sparser; VSI publishes security alerts on their portal. The pre-VSI HP-era TCP/IP Services bugs are partially CVE-tagged.

### Notable incidents (verified-to-the-extent-public-reporting-allows)

- **Maersk NotPetya 2017** — the public account focuses on Active Directory compromise. Cross-reference `[[reference-active-directory-windows-security]]` for the AD-pivot mechanism (file path `software/platform-security/active_directory_windows_security.md`).
- **MOVEit / Cl0p 2023-2024** — affected enterprise file-transfer infrastructure that often serves as the gateway between mainframe and distributed systems. The mainframe was not the breach origin in most cases, but the breach often included data extracted from mainframe-fed file flows.
- **HCA Healthcare 2023 data breach** — large-scale data exposure. The relationship to mainframe infrastructure is not clearly documented in public reporting; HCA's environment includes substantial mainframe presence but the breach disclosure does not anchor specifics. `[unverified involvement of mainframe substrate]`.
- **SHARE / GSE conference disclosures (2023-2026)** — small but consistent stream of integrity bugs presented at the user-group level, often months ahead of or alongside CVE assignment. Track the SHARE security project agendas for current research; the named researchers in §2 anchor the community.

### APAR vs. CVE

IBM ships fixes for z/OS integrity bugs under APAR numbering. APARs do not always receive CVE assignment. The implication for risk modeling: counting public CVEs underestimates the actual fixed-bug rate. Operations teams that patch by CVE tracking systematically lag the integrity exposure being remediated.

---

## 14. Detection and defense

### SMF — System Management Facility

SMF is the z/OS audit trail. Every interesting system event is recorded as an SMF record. Record types relevant to security:

| SMF Type | Subject |
|----------|---------|
| 14 / 15  | Dataset access (read / write) |
| 17 / 18  | Dataset scratch (delete) / rename |
| 30       | Job start / step end / job end |
| 42       | DASD service / SMS events |
| 60-69    | VSAM dataset open/close, alter |
| 80       | RACF — authentication, authorization, profile changes |
| 81       | RACF database initialization |
| 83       | RACF audit records (extended) |
| 90       | System status changes |
| 92       | USS file activity |
| 100/101/102 | DB2 — statistics, accounting, performance/audit trace |
| 110      | CICS — transaction execution |
| 119      | TCP/IP / FTP / Telnet |

**SMF type 80 is the RACF audit trail.** Failed logons, successful logons of privileged users, profile changes, PERMIT changes, dataset access violations — all here. A z/OS security program with no real-time view of type 80 records is operating blind.

### SMF → SIEM ingest

Modern operations ship SMF to Splunk / QRadar / Sentinel / Elastic / Datadog via one of:
- **Syncsort / Precisely Ironstream** — commercial SMF-to-SIEM bridge.
- **IBM Common Data Provider for z Systems** — IBM's first-party bridge.
- **Homegrown SMF dumps via IFASMFDP** — works, has been in use forever, requires post-processing.

The bridge component is itself an attack surface — it has access to every audit record. Cross-link `[[reference-detection-engineering]]` for the broader detection-engineering framework that applies to SMF-driven detection rules. Sigma has a small but growing set of z/OS rules; the community is led by people who do both z/OS and modern-SIEM work, of which there are a few.

### Native auditing tools

- **DSMON** — RACF Data Security Monitor. Generates standard reports on RACF configuration.
- **IRRRID00** — RACF remove ID utility. Generates commands to clean up references to residual user IDs and group names.
- **IRRDBU00** — RACF database unload utility. Produces a flat file representation of the entire RACF database for offline analysis.
- **IRRADU00** — SMF type 80 unload utility. Equivalent for the audit trail.
- **ACFRPT** family — ACF2 reporting.
- **TSS LIST / TSS WHOHAS** — Top Secret reporting.

For IBM i: `DSPAUTUSR`, `DSPAUDJRNE` (display audit journal entries), `WRKAUTL` (work with auth lists). The QAUDJRN journal is the audit-trail equivalent of SMF.

For OpenVMS: `ACCOUNTING` and the audit server (set up via SET AUDIT) feed the security audit trail.

### Hardware integrity

z/OS hardware crypto and tamper resistance:
- **CPACF (CP Assist for Cryptographic Functions)** — instructions on the central processor that implement symmetric crypto (AES, DES variants, SHA), bulk hashing, random number generation. Not a tamper-resistant boundary by itself; just hardware acceleration.
- **Crypto Express (CEX)** — a tamper-evident HSM card. Modern variants (CEX7S) are FIPS 140-2 Level 4 certified. Key material can be encrypted under a master key that never leaves the card; clear-key operations are also supported.

Cross-link `software/crypto-trust/cryptography_expertise.md` for the broader crypto primitive treatment. CPACF and CEX are first-class hardware crypto in industry; the cryptography document covers them at the level of "what is the right algorithm" and this section covers them at the level of "how is the key material protected on the mainframe."

### Modernization risk — lift-and-shift to cloud

Banks are not eliminating mainframes; they are extending them. IBM Cloud-for-z (Wazi as a Service), AWS Mainframe Modernization, Microsoft Azure Mainframe Migration, and Google Cloud's mainframe partnerships all create *hybrid* environments where mainframe workloads run in cloud infrastructure or where cloud workloads call into mainframe transactions. The attack surface in these environments is:
- Cloud-IAM-on-top-of-mainframe-IAM (`[[reference-cloud-iam]]`).
- API gateways translating REST → CICS or REST → IMS — the API gateway becomes a single high-leverage authentication boundary.
- Mainframe data replicated into cloud data lakes — same auth at rest? Same audit trail?
- COBOL-translated-to-Java microservices, retaining COBOL structural bugs in a microservice context.

The honest summary: most modernization projects add the cloud's attack surface to the mainframe's, rather than replacing the mainframe's surface. The risk model is composite, not substitutive.

### Commercial scanning and reporting tools

- **IBM zSecure Suite** (originally Consul Risk Management, acquired by IBM 2007; the suite includes Admin, Audit, Alert, Visual, Command Verifier). Commercial RACF / ACF2 / Top Secret scanning.
- **Vanguard Integrity Professionals** — commercial RACF audit and reporting.
- **BMC AMI Security** (BMC acquired Compuware 2020; this folded into the AMI portfolio). Commercial z/OS security analytics.
- **Fortra / Powertech for IBM i** — IBM i security audit suite.
- **Broadcom's own ACF2 / Top Secret administrative tools** — the second-party suite for the Broadcom ESMs.

`[unverified specific deployment claim]`: I won't quote market share or "customer count" numbers for any of these; their own marketing pages overstate, and there is no independent census.

---

## 15. Honest failure modes (where this document is thin)

### The skills gap is load-bearing

This document is an orientation, not a deep-dive. It points a security engineer or VR auditor at the right primitives, the right vocabulary, the right named researchers, and the right structural pitfalls. It does not replace months of operational exposure to z/OS, IBM i, or OpenVMS. A reader who finishes this document and goes audit a CICS region in production will get more answers wrong than right on the first pass; that is the honest expectation, not a failure of the document.

### Vendor-NDA-blocked detail

Substantial portions of the z/OS integrity-bug stream ship under IBM proprietary APAR numbering, not CVE. The public CVE corpus systematically under-counts the actual rate. Operations teams that have an IBM relationship see APAR-numbered fixes monthly; everyone else sees a sparse CVE feed quarterly. The same dynamic applies to IBM i. For OpenVMS, VSI's disclosure cadence is small and the historical HP-era backlog of unfixed-or-quietly-fixed issues is not auditable from outside.

### Classified deployments under air-gap-relative

Real OpenVMS attack surface in defense and nuclear is classified. Real IBM i attack surface in certain financial-services back-offices is contractual-confidential. Real z/OS attack surface in government tax / social-insurance / treasury contexts is rarely discussed publicly. The public corpus is systematically biased toward financial-services anchors that *can* be discussed (and toward research presentations at SHARE / GSE / BSidesLV that are intentionally public). What's not in the public corpus is not nothing; it's a structural blind spot.

### 2024-2026 modernization is a moving target

The COBOL-to-Java translation tooling, the IBM Cloud-for-z deployment patterns, and the AI-assisted modernization workflows (Watson Code Assistant for Z, Micro Focus' AMC translation, AWS Blu Age) are evolving fast enough that any deep technical treatment is stale by the time it ships. This document avoids the specifics of any one modernization product and treats the *class* — translated COBOL retains COBOL bugs, hybrid deployments compose attack surfaces, AI-augmented translation introduces new translation-bug shapes (cross-link `ai_assisted_coding_tool_security_expertise.md` §4 for the AI-translation-bug class). Names of specific products will date.

### COBOL footguns subsection is shorter than it should be

The COBOL programming language has decades of accreted footguns. §12 covers the standout structural and security-relevant cases. A complete COBOL footgun treatment — copybook namespace collisions, DECIMAL POINT IS COMMA locale assumptions, EBCDIC ↔ ASCII conversion edge cases, file status code handling, ACCEPT/DISPLAY environment differences across vendors, OCCURS DEPENDING ON dynamic arrays, sort exits, the CALL BY REFERENCE vs. BY CONTENT vs. BY VALUE distinction in COBOL 2002 / 2014 — would double this section's length. Marking as queued for future deepening: "COBOL footguns expansion" as a separate document in the language-footguns class.

### IBM i and OpenVMS research-community thinness

The named-researcher density for IBM i is lower than z/OS. For OpenVMS it's lower still. This is itself a finding the document surfaces but cannot remediate. Recruiting more public research attention to these substrates is a community problem; the security-of-the-thing depends on the size of the community auditing it, and these are both small communities.

### The four threads are not equally treated

z/OS gets the most weight (§3-9). IBM i gets §10. OpenVMS gets §11. COBOL gets §12. The weighting reflects the public-corpus weighting, not necessarily the operational-risk weighting. An auditor walking into an IBM i shop should not read §3-9 and assume the principles transfer; they do not, and treating IBM i as "the small z/OS" is a category error.

### Crypto-on-mainframe is undertreated

CPACF and Crypto Express get a paragraph in §14. The actual depth of key-management, master-key custody, key-ceremony procedure, RACF integration with ICSF (Integrated Cryptographic Service Facility), HSM-domain isolation across LPARs — none of that is covered here. A future deepening into "crypto on the mainframe" would warrant its own document or an explicit subsection of `software/crypto-trust/cryptography_expertise.md`.

---

## 16. Cross-link cluster

- `[[reference-distributed-authz]]` — the broader AuthN / AuthZ framework. RACF / ACF2 / Top Secret are single-organization closed-world counterparts to the federated and distributed AuthZ systems treated there.
- `[[reference-cloud-iam]]` — modern cloud IAM. Mainframe-modernization-to-cloud composes the cloud IAM threat model on top of the mainframe IAM threat model; both have to be reasoned about, not one or the other.
- `[[reference-dfir-methodology]]` — IR generally. Mainframe-specific IR — SMF preservation, RACF database forensic imaging, CICS region snapshotting, USS filesystem capture — is a specialized sub-discipline that the broader DFIR document does not currently cover.
- `[[reference-detection-engineering]]` — SMF → SIEM ingest is the runtime detection substrate. The Splunk / QRadar IBM Z content packs build on this.
- `[[reference-language-footguns-class]]` — language-level unsafe primitives. COBOL belongs in this class and is added here.
- `[[reference-shell-injection]]` — applies to z/OS USS shell, IBM i PASE, and OpenVMS DCL. The three-class taxonomy (CWE-78 / CWE-88 / CWE-150) carries unmodified.
- `software/crypto-trust/cryptography_expertise.md` — CPACF, Crypto Express crypto primitives. The mainframe-specific hardware crypto layer is a key-management substrate worth a deeper treatment than this document affords.
- `software/platform-security/active_directory_windows_security.md` — the Windows / AD parallel auth universe. Modernization-bridge architectures (mainframe + AD-integrated authentication, mainframe via SAML through an AD-fronted IdP) compose the two threat models.
- `[[reference-bug-hunting-first-principles]]` — first-principles auditing lens. Applies to mainframe substrates with the caveat that the substrate-specific primitives (APF, object authorities, DCL symbol substitution) have to be in working memory for the first-principles lens to land.
- `[[reference-vr-methodology]]` — VR methodology. Mainframe VR is an open community-research frontier where the four canonical methods (code review, variant analysis, fuzzing, patch diffing) apply unmodified but with substrate-specific tooling and corpora.
