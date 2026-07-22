# Staff-Level Adversarial AppSec Guiding Principles
## Synthesized from John Heasman

> John Heasman is a UK-born, Oxford-educated security researcher (M.Eng, Computing Science) who
> spent a decade at NGS Software (Next Generation Security Software, London/Seattle) as Director
> of Research / VP of Research before transitioning through DocuSign (Deputy CISO) and Chegg
> (CISO) to CISO at Proof. He holds CESG CHECK Team Leader certification. His public output
> spans two seminal offensive security books, a series of landmark Black Hat/DEF CON presentations
> on firmware rootkits, a documented blog series on Java browser plugin exploitation, a Stanford
> CS155 guest lecture on fuzzing, and a body of CVE advisory work covering OpenOffice, Java,
> RealPlayer, Microsoft Exchange, PostgreSQL, and more.
>
> Books: *The Database Hacker's Handbook* (Wiley, 2005, with Litchfield/Anley/Grindlay);
> *The Shellcoder's Handbook, 2nd Edition* (Wiley, 2007, with Anley/Linder/Richarte).
> Blog: heasman.blogspot.com ("aut disce, aut discede" — "Either learn, or leave")
>
> Sources: Black Hat / DEF CON / ToorCon / Stanford slides and papers; CVE/NVD/CERT advisories;
> blog archives; O'Reilly chapter listings; PortSwigger/PentestMonkey recommendations; TaoSecurity
> conference writeups; LinkedIn; NCC Group research pages.

---

## 1. Core Philosophy

### "Either learn, or leave" — the attacker's epistemological posture

The blog's Latin title is not decorative. Offensive security is a discipline of continuous, deep
learning — not pattern-matching against a checklist. Every vulnerability class has a root cause.
Every mitigation has a bypass. The practitioner who stops at the first working proof-of-concept
and does not ask "why does this work, and what else follows from that mechanism?" is operating
below the threshold of genuine expertise.

This is the distinction between a scanner operator and a researcher: the researcher derives the
vulnerability from first principles and can therefore find it in a new context where the scanner
has no signature.

### Depth over breadth — but the full stack is in scope

Heasman's career arc illustrates a disciplined specialization pattern: database internals →
Windows kernel exploitation → firmware persistence → browser plugin security → enterprise AppSec
program management. Each transition is anchored in deep mastery of the previous layer. The
firmware rootkit work was not possible without kernel-level understanding. The Java exploitation
work required understanding the JVM's native code interfaces at the same level as the underlying
OS.

The lesson: you may not need to know everything at all times, but the attack surface does not
respect your preferred layer. A complete adversarial thinker understands the full stack from
firmware to the browser DOM.

### The attacker's advantage is asymmetry — exploit it precisely

Defenders must protect every entry point. Attackers need one. Effective offensive research does
not try to enumerate all vulnerabilities; it looks for the structural asymmetry — the category of
flaw that is systematically present because of how something was designed or built, not because
of a single engineering mistake. The ACPI rootkit was not a one-off; it was a consequence of the
design of the AML interpreter. The Java SOP bypasses were not isolated bugs; they were a
consequence of how the JVM resolved URL authority components.

Finding the structural cause means you find the full class of vulnerabilities, not just one CVE.

---

## 2. Vulnerability Research Methodology

### Systematic fuzzing: know what you are targeting before you fire

From the Stanford CS155 lecture and the ActiveX property bag research:

**When to fuzz:**
- Parsers of complex, attacker-controlled input formats (file formats, protocol messages, API
  parameters) — especially those implemented in native code
- Interface boundaries where type conversions occur (Java-to-JNI, COM dispatch, RPC marshaling)
- Any code path that accepts untrusted data and performs arithmetic on length or offset fields

**When NOT to fuzz:**
- Logic-layer flaws (authorization, business logic, trust boundary violations) — fuzzing is the
  wrong tool; code review and manual analysis are correct
- Targets where coverage tools show you cannot reach the interesting code paths

**The property bag gap** — a canonical example of systematic coverage failure:
Most ActiveX fuzzing tools (COMRaider and contemporaries) exercised COM dispatch interfaces but
omitted `IPersistPropertyBag` / `IPropertyBag`. Any control implementing these for property
persistence was systematically missed. The fix was straightforward: enumerate all implemented
interfaces via `IUnknown::QueryInterface` before deciding what to fuzz. The Yahoo Messenger heap
overflow (`ymmapi.ymailattach.1`, `TextETACalculating` property) was found this way — a signed,
widely distributed component, exploitable via a property the fuzzer never reached.

Generalized: **know the full interface surface of your target, not just the most obvious
attack surface.** Do not rely on existing tool coverage as ground truth for what exists.

### Pre-installation vulnerability analysis

From the "Hunting Bugs Pre-Installation" blog post: installers (MSI, InstallShield) are a
largely underaudited attack surface. The MSI file format is a structured database queryable via
SQL using Windows SDK tools (Orca).

Key tables to examine:
- `CustomAction` — commands executed during install; inspect for ACL weaknesses, `cacls.exe`
  misuse, writable paths
- `ServiceInstall` — service accounts, passwords in plaintext, ServiceType/StartType
- `LockPermissions` — ACL grants on files/registry keys post-install
- `File` — bundled library versions; compare against known-vulnerable versions of OpenSSL, Zlib,
  LibCurl, etc.

Live example: Cisco VPN Client MSI — `CustomAction` table contained:
```
cacls.exe "[INSTALLDIR]." /t /e /g "NT AUTHORITY\INTERACTIVE":C
```
This grants Change permission to all interactive users on the install directory tree — a
privilege escalation that could be predicted and scripted before the installer was ever run.

This technique generalizes: attackers analyze targets before engagement. Security teams should
analyze software before deploying it to endpoints. The pre-install analysis window is zero cost
and yields defects that would take a post-exploit investigation to find otherwise.

### Buffer overflow taxonomy: know the root cause, not just the symptom

From "Three Categories of Buffer Overflow in the JRE" and Chapter 24 of the Shellcoder's
Handbook:

**Category 1: File format parsers implemented in native code**
Performance-critical or legacy parsers (BMP, GIF, JPEG, ICC color profiles, TrueType fonts) are
often implemented in C/C++ beneath the managed runtime. They inherit all C memory safety failures.
The JRE TrueType vulnerability (SunSolve 103024) exploited a missing bounds check on writes to
the Control Value Table in the TrueType font VM. Importantly, the heap was executable because
Java and DEP were incompatible — the managed runtime itself was the mitigation bypass.

**Category 2: Platform API wrapper type conversions**
Managed languages wrap native platform APIs with type conversions. Conversion errors — passing a
Java `int` to a native function expecting a `short`, or a signed length to an unsigned arithmetic
operation — generate classic C integer overflow / heap overflow chains without any obvious C code
in scope.

**Category 3: Underlying platform API vulnerabilities triggered through thin wrappers**
A JRE call to `gethostbyname()` through a thin JNI wrapper inherits any platform-level buffer
overflow in the resolver. The managed layer adds no safety.

Implication: **finding all vulnerabilities in a managed runtime requires auditing native code
beneath the runtime, not just the managed layer.** This applies equally to JavaScript engines,
Python C extensions, .NET P/Invoke, and any other managed-to-native interface.

### Exploit construction: map the primitive to the target

From the TrueType exploitation (SunSolve 103024) and "Three Categories":

The CVT (Control Value Table) overflow provided an attacker-controlled write to a calculated
offset from the CVT base. Exploitation required:
1. **Establish the primitive:** an overlong CVT write instruction causes write to `CVT_base + n`
   for attacker-controlled `n`
2. **Read to locate target:** use a malformed read instruction to disclose memory relative to the
   CVT — find a function pointer at a known offset
3. **Write to overwrite:** overwrite the function pointer with heap address
4. **Execute:** trigger the overwritten function

Each step is a distinct primitive that must be chained deliberately. The key insight: a write
primitive to an unknown location is worthless without a read primitive to establish geometry.
Design exploit chains from primitives up, not from payload down.

---

## 3. Firmware and Hardware Attack Surface

### ACPI: the OS executes BIOS-authored code at runtime

From "Implementing and Detecting an ACPI BIOS Rootkit" (Black Hat Federal 2006, BH Europe 2006):

ACPI Machine Language (AML) is a bytecode language compiled from ACPI Source Language (ASL).
The OS's ACPI driver contains a full AML interpreter that executes code from BIOS-resident ACPI
tables (DSDT, SSDT) on demand — during power events, device attach/detach, and system
initialization. This interpreter has direct access to I/O address space, memory-mapped I/O, and
(on some implementations) physical memory via `OperationRegion` declarations.

**Attack process:**
1. Extract AML from target BIOS
2. Decompile to ASL; locate initialization control methods that execute early
3. Append malicious ASL (e.g., a method that overwrites a kernel data structure)
4. Recompile ASL → AML
5. Flash the modified BIOS (requires physical access or root + unsigned flash utility)
6. On reboot, ACPI interpreter executes malicious AML before OS security subsystem is fully
   initialized; bootstrap code patches kernel in memory

**Windows demo:** Overwrite `SeAccessCheck` (the access control decision function) to always
return TRUE. Result: all security checks silently pass. This is not ring-0 exploitation — it is
using a designed-in OS facility (ACPI interpreter) to subvert a security function before the
security function is ever called on the attacker's behalf.

**Key properties as a persistence mechanism:**
- Survives OS reinstall (code is in BIOS, not on disk)
- AML interpreter is platform-independent; the ASL can query OS version and branch accordingly
- No disk footprint; invisible to all OS-level forensics
- Requires only a bootstrap payload in BIOS (tens of KB available); full rootkit loaded into RAM

**Detection:** Only reliable detection requires dumping and analyzing BIOS ROM contents. OS-level
detection tools are blind by design — they run after the ACPI interpreter has already executed.

**Threat model:** Requires physical access or a pre-existing root exploit plus an unsigned BIOS
flash utility. Suitable for targeted persistent access, not mass exploitation.

### PCI option ROMs: the TPM bypass

From "Implementing and Detecting a PCI Rootkit" (Black Hat DC 2007):

Intel SecureFlash and Phoenix TrustedCore implement TPM-backed verification of BIOS images,
preventing unsigned BIOS modifications. The response: PCI option ROMs.

PCI expansion cards (network adapters, video cards, SCSI controllers) contain flashable option
ROMs that execute at POST, before the OS boots and before any TPM measurement. On systems without
Secure Boot or TPM-based option ROM verification, these execute without signature checks.

Properties:
- Zero footprint on disk; invisible to all OS forensics
- Survives OS reinstall and OS re-image
- No dependency on BIOS flash utility; requires only physical access to the PCI device or a
  compromised driver that can access the flash interface
- The bootkit executes before any OS security measurement

This extended the ACPI rootkit concept to systems with BIOS write protection, demonstrating that
the firmware attack surface is not a single choke point but a set of independently flashable
components.

### EFI / UEFI: a richer firmware attack surface than legacy BIOS

From "Hacking the Extensible Firmware Interface" (Black Hat USA 2007, DEF CON 15):

EFI replaces the 25-year-old BIOS architecture with a richer framework:
- FAT filesystem (EFI System Partition) for firmware and loader storage
- Network stack, scripting, and driver model built into firmware
- NVRAM-backed configuration including the boot loader path
- Partial open-source reference implementation (Intel's EFI Developer Kit)

**EFI attack vectors (in increasing stealth):**

1. **Bootloader modification** — simplest; modifiable via disk access; defeated by Secure Boot
2. **NVRAM boot variable manipulation** — modify the EFI boot path variable to point to a
   malicious loader; survives OS reinstall
3. **Firmware reflash** — same as legacy BIOS attack but with richer EFI scripting available
4. **EFI driver implementation flaws** — memory safety bugs in EFI drivers executing before OS;
   exploitable via malicious boot media or DMA

**System Management Mode (SMM):**
SMM is the deepest available execution context — below ring-0, invisible to the OS, triggered by
System Management Interrupts (SMI). SMM code:
- Cannot be observed by the OS or any OS-level tool (by architecture)
- Defeats hardware breakpoints set in the OS
- Runs in a physically isolated memory region (SMRAM) mapped out of OS address space
- Can be triggered by I/O events, timers, and external events — creating a persistent side channel

An SMM rootkit is architecturally analogous to a Type-1 hypervisor rootkit: it runs beneath the
OS, observes everything, and cannot be detected by anything running above it. Detection requires
hardware-level inspection or a trusted boot measurement chain (TPM + TXT).

**Threat model:** The escalation path is: browser/application vulnerability → kernel privilege
escalation → firmware access → SMM persistence. The firmware layer is the persistence endgame;
it survives all remediation short of hardware replacement or a verified firmware flash from a
trusted source.

---

## 4. Java and Browser Plugin Security

### The JRE is a native code attack surface wearing a managed mask

All of the following JRE components involve native C/C++ code and are therefore subject to memory
safety failures:
- Font rendering: TrueType, Type1 (control value table, native VM instructions)
- Image decoders: BMP, GIF, JPEG, PNG, ICO
- Color management: ICC profiles
- Java Web Start (JNLP): file format parsing, argument handling
- JNI: all native method wrappers

Finding bugs in the JRE does not require Java expertise. It requires C/C++ auditing skills
applied to the native code beneath the managed runtime.

### Same-origin policy bypass via URL authority parsing (Sun Alert 233324)

The core of Heasman's Java SOP research (BH 2008 / blog series):

Java's URL class resolves the authority component (hostname:port) to determine the origin of
loaded code. The bug: applet code URLs containing a period character triggered internal
canonicalization that converted slashes to dots, causing the authority reported to the security
manager to differ from the host the class was actually loaded from.

Exploitation chain:
1. Host malicious class at `http://evil.example.com/foo`
2. Specify in applet tag: `code="http://evil.example.com/foo"` with `codebase="http://victim.com"`
3. JVM loads class from `evil.example.com` but reports origin as `victim.com`
4. Applet is granted `victim.com` permissions and can make network requests to `victim.com`

**Drive letter discovery** (escalation to full code execution via extensions directory):
Extensions JARs in `jre/lib/ext/` are granted `java.security.AllPermission` by default policy.
To exploit:
1. Discover the drive letter: `Toolkit.getDefaultToolkit().getDesktopProperty("win.xpstyle.dllName")`
   returns a full path like `E:\WINDOWS\Resources\themes\Luna\Luna.msstyles`
2. Set applet `codebase="file:E:\Program Files\java\jre1.6.0_03\lib\ext"`
3. With AllPermission: `Runtime.getRuntime().exec()` or `System.loadLibrary()` → full OS access

**Workaround for class name mismatch:** Compile class with any name, then hex-edit the class
file's `this_class` constant pool entry to match the URL path string. The JVM's class loader
resolves by constant pool reference, not file name.

### JNLP argument injection via property name escaping (Sun Alert 233323)

Java Web Start processes JNLP property tags and passes them as JVM arguments. By inserting
`/` characters into property names, an attacker could escape the property name field and inject
arbitrary JVM arguments — including `-classpath` pointing to a malicious JAR. Demonstrates that
argument injection in configuration-file parsers follows the same pattern as SQL injection and
command injection.

### JAR integrity: verification vs. validation mismatch

Unsigned files appended to a signed JAR do not trigger verification exceptions in `JarFile`. The
`jarsigner` tool's validation mode was separately fooled by files prefixed `META-INF/SIG-`. The
mismatch between the two verification paths allowed appending a malicious `java.policy` file to a
signed JAR, granting the attacker-controlled policy file priority in the security manager.

General principle: **integrity verification has multiple implementation layers that may not
check the same thing.** When two components both claim to verify the same artifact, probe whether
they verify the same set of bytes in the same way.

### NTLM hash theft via unsigned applet + localhost server

An unsigned applet can:
1. Bind an HTTP server on `localhost`
2. Serve content tagged as `file://` protocol (Local Intranet zone)
3. Trigger NTLM authentication challenge from the browser
4. Capture the NTLM hash
5. Offline-crack or relay the hash

This works because Windows classifies localhost as the Local Intranet zone, which has different
security policy than the Internet zone. The applet never touches the filesystem — it constructs
the authentication exchange entirely in-process.

---

## 5. Database Security (from *The Database Hacker's Handbook*)

*The Database Hacker's Handbook* (Wiley, 2005, with Litchfield/Anley/Grindlay) covers seven
database platforms: Oracle, IBM DB2, Informix, Sybase ASE, MySQL, Microsoft SQL Server,
PostgreSQL.

### The full database attack chain

The book's structure defines the complete attack surface for each platform:

1. **Discovery and enumeration** — identifying database version, instance name, listener ports,
   default accounts, installed components
2. **Authentication attacks** — weak/default credentials, hash capture, authentication bypass
3. **Privilege escalation via SQL** — exploiting stored procedures, triggers, and user-defined
   functions that execute with elevated database privileges
4. **Platform-specific buffer overflows** — native code in the database server (format string
   bugs, heap overflows in extended stored procedures)
5. **OS-level escalation** — from database service account to operating system
6. **Post-exploitation** — data exfiltration, persistence

### PostgreSQL: the LOAD privilege escalation

CVE-2005-0227 (discovered by Heasman at NGS): PostgreSQL's `LOAD` command allowed any database
user — not just superusers — to load arbitrary shared libraries into the database server process.
Because the database server runs as a system user, this immediately escalated any authenticated
database user to OS-level code execution.

This is a canonical example of a **functionality that exists for legitimate reasons (loading
extensions) but that is unacceptably broad in scope** (any user, not just trusted admin accounts).
The fix: restrict `LOAD` to superuser accounts.

### Microsoft Exchange TNEF: remote pre-auth code execution

CVE-2006-0002 (Heasman + Mark Litchfield, NGS): A buffer overflow in Exchange Server's parsing
of TNEF-encoded email attachments (the winmail.dat format used by Outlook). TNEF parsing occurs
before authentication — an unauthenticated attacker sends a malformed email to the Exchange
server; the server processes it and executes attacker-supplied code in the context of the
Exchange service. MS06-003, Critical.

This is the class of vulnerability that terminates careers and requires emergency patching:
**unauthenticated remote code execution in an internet-facing service that every enterprise
runs.** TNEF is a protocol from the 1990s with no modern security review. Protocols never
intended to face the internet routinely end up doing so when wrapped in higher-level services.

### OpenOffice: multiple native-code vulnerabilities in a document suite

Four CVEs from Heasman's NGS advisory work against OpenOffice.org 2.x:

- **CVE-2006-5870**: Heap overflows in WMF/EMF metafile handling. `EMR_POLYPOLYGON` and
  `META_ESCAPE` records: a 32-bit length value is cast to 16-bit for the allocation calculation
  but the 32-bit value is used for the subsequent fill loop. Classic integer truncation → heap
  overflow.
- **CVE-2007-0238**: Stack-based buffer overflow in StarCalc (spreadsheet) parser.
- **CVE-2007-0239**: Input validation failure in hyperlink metacharacter handling — clicking a
  malicious link executes attacker-specified commands.
- **CVE-2007-0245**: Heap buffer overflow in RTF parser: `prdata` tag where the first size token
  is smaller than the second size token that drives the copy loop.

**Pattern:** Office/document suite native parsers are written in C/C++ for performance and
handle complex binary format specifications. They are rarely audited with the same rigour as
network-facing servers. The attack vector (opening a document) is extremely low-friction — social
engineering is essentially solved for document delivery.

---

## 6. Windows Kernel Exploitation (from *The Shellcoder's Handbook, 2nd Edition*)

*The Shellcoder's Handbook* (Wiley, 2007) includes Chapter 27: "Hacking the Windows Kernel,"
covering the architectural and exploitation-technique material summarized below. (Note: the book
does not attribute individual chapters to named authors in its front matter; Chapter 27 is
consistent with Heasman's known research area.)

### The Windows kernel attack surface taxonomy

**Stack overflows in kernel-mode code:**
Kernel stacks are much smaller than user-mode stacks (typically 12–16KB on 32-bit Windows). The
GS compiler flag (`/GS`) places a stack cookie before the return address — but the attacker can
overwrite enough data to control execution before the cookie check fires (e.g., by overwriting a
local function pointer called before function return). Kernel heap overflows follow similar
mechanics to user-mode heap exploitation but without userland heap mitigation tools available for
analysis.

**Insufficient validation of user-mode addresses:**
Kernel code that copies data from user-mode buffers must validate the pointer before dereference.
Failure to do so allows a user-mode process to pass a kernel-space address, causing the kernel
to read or write kernel memory at an attacker-specified address. ProbeForRead/ProbeForWrite are
the correct Windows kernel APIs; code that omits them is exploitable.

**IOCTL handlers as an attack surface:**
Device drivers expose IOCTLs (I/O control codes) that can be sent by low-privileged user-mode
processes. The IOCTL handler receives a buffer from user space and an I/O stack location
containing input/output buffer sizes. Bugs: assuming input buffer is null-terminated, using
output buffer size for read length, performing arithmetic on attacker-controlled size fields.
IOCTL handler auditing is systematic: enumerate all IOCTLs exposed by a driver, call each with
malformed buffers.

**Kernel-mode payloads:**
User-mode shellcode concepts (return address overwrite → shellcode execution) adapt to kernel
mode with different targets:
- **Privilege elevation:** Modify the token pointer in the calling process's EPROCESS block to
  point to the System process's token — elevate any process to SYSTEM without touching user space
- **Arbitrary user-mode payload execution:** Queue an APC to a user-mode thread, return to user
  space for full shellcode execution with kernel privileges as launching platform
- **Security subversion:** Patch `SeAccessCheck`, `NtQuerySystemInformation`, or SSDT entries
- **Rootkit installation:** Load a kernel module from an attacker-controlled path; hook
  SSDT/IDT/IRP dispatch tables

---

## 7. Web Application Security

### SQL injection is an injection architecture failure, not a single bug

From the Database Hacker's Handbook and documented NGS advisory work:

SQL injection is not a "missing input sanitization" bug. It is an architectural failure to
separate code from data. Every dynamic SQL construction that concatenates attacker-controlled
strings into a query is potentially injectable, regardless of the filter in place. Parameterized
queries / prepared statements are not a better sanitizer — they are the only correct architecture.

The impact spectrum is wide: information disclosure (error messages), authentication bypass
(`' OR '1'='1`), union-based extraction, blind inference (boolean/time), stored procedure abuse
(xp_cmdshell, UTL_HTTP, DBMS_PIPE), and OS code execution via extended functionality.

Database platform matters for impact:
- **SQL Server:** `xp_cmdshell` (OS command execution as service account), stacked queries
- **Oracle:** `UTL_HTTP`, `UTL_FILE`, Java stored procedures (if Java enabled)
- **MySQL:** `INTO OUTFILE` / `LOAD DATA INFILE` for file read/write (path traversal dependent
  on filesystem permissions); `system()` in UDFs if loaded
- **PostgreSQL:** `COPY TO/FROM PROGRAM` (PostgreSQL 9.3+) for OS command execution as the
  database service user; `LOAD` (pre-CVE-2005-0227 fix)

### The fuzzing approach to web applications

From "Web Application (In)Security" (Black Hat training, 2010/2011) and Stanford lecture:

Web application fuzzing targets:
- Input parameters (GET, POST, cookies, HTTP headers, JSON/XML body)
- Serialized formats (Java serialization, AMF/Flex remoting, WCF/Silverlight)
- File uploads (content-type mismatch, malformed format headers, ZIP slip)
- NoSQL query injection (MongoDB operator injection, CouchDB view injection)
- Server-Side JavaScript injection (Node.js `eval`, template injection)

2011 additions to the Black Hat training reflected the expanding surface: Ruby on Rails
parameter handling vulnerabilities (mass assignment, YAML deserialization), Flex AMF
deserialization, HTML5 cross-origin messaging (`postMessage` origin validation failures), NoSQL
injection patterns.

---

## 8. Enterprise AppSec Program Design

Heasman's later-career work at DocuSign, Chegg, and Proof synthesizes offensive research depth
into scalable, defensive program design. The following represents his documented organizational
approach.

### The True Positive Process: eliminate vulnerability classes, not individual bugs

From BSides Knoxville — "Doing More in AppSec by Doing Less":

Treating every finding from a penetration test or bug bounty as an independent ticket to be
remediated one by one does not scale. The correct model:

1. **Collect true positives** from penetration tests, bug bounty, SAST/DAST
2. **Determine root cause** in collaboration with engineering (not just symptoms)
3. **Abstract to an anti-pattern** — what general coding pattern produced this class of flaw?
4. **Prioritize by prevalence** — how many instances of this anti-pattern exist across the
   codebase?
5. **Implement a countermeasure that eliminates the class** — fix the anti-pattern, add a
   framework-level control, add a linting rule, add a unit test fixture
6. **Verify the class is gone** — re-scan, re-test; do not close until the root cause is
   addressed structurally

"If everything is a priority, nothing is a priority." AppSec programs that attempt to remediate
every finding in parallel achieve low throughput on everything. Programs that identify the
highest-prevalence vulnerability class and eliminate it entirely achieve lasting reduction in
attack surface.

This is the offensive researcher's root-cause methodology applied to defense: finding the
structural cause and closing the class, not patching individual instances.

### Pre-installation analysis as a security practice

The MSI auditing methodology generalizes directly into modern supply chain security:
- Audit third-party software before deploying to endpoints
- Examine installers for: bundled outdated libraries, weak ACLs post-install, hardcoded
  credentials in service installation parameters, CustomAction commands that grant excessive
  permissions
- Use the vendor's own tooling (Orca for MSI, npm audit, pip-audit) to inspect packages before
  installation in CI/CD pipelines

The attacker analyzes software before deploying an exploit. The defender should analyze software
before deploying it to production.

### Vulnerability classification and triage discipline

From the JRE CVE-2018-2811 research (discovered at DocuSign):

A weak ACL on the `ProgramData\Oracle\Java` directory allowed a low-privileged local user to
plant a `jvm.cfg` file pointing to a malicious `jvm.dll`. Result: any process that loaded the
JRE (including elevated processes) loaded the attacker's DLL.

This class of vulnerability — **DLL hijacking / search order / configuration file injection via
weak ACL** — is systematically present in software that:
- Writes configuration or temporary files to user-accessible paths
- Reads configuration from paths that lower-privileged users can write
- Loads libraries from relative paths or PATH-dependent paths

A staff-level security engineer classifies this not as "one JRE bug" but as a question: how
many of our deployed services have writable configuration or library paths that could be
exploited by a local attacker who has compromised any service account?

### Patch lifecycle and advisory disclosure posture

From the MS06-003 advisory handling:

NGS withheld full technical details for three months after the Microsoft patch (published January
2006 patch, NGS full advisory April 2006). The principle: coordinated disclosure with a fixed
deadline. The attacker window opens at patch release (patch diffing); the defender's window is
the same period. Extended technical publication after the patch gives defenders time to deploy
while attackers race to exploit before deployment is complete.

Modern coordinated disclosure (90-day standard from Google Project Zero) formalizes this: the
researcher and vendor agree on a timeline; full details publish at deadline regardless of patch
status, to maintain researcher credibility and vendor patch-urgency incentives.

---

## 9. Instrumentation and Reverse Engineering

### Dynamic analysis: set breakpoints where assumptions are, not where code is obvious

From the JRE URL authority research: verification of the SOP bypass required setting JSwat
debugger breakpoints on the `URL` constructor to observe how the authority component was
resolved. The bug was in the interaction between two components that each behaved correctly in
isolation.

When investigating a suspected vulnerability:
1. Identify the assumption you are testing
2. Find the execution point where that assumption is first observable
3. Instrument there — not at the final crash site

Crash-driven analysis (wait for the exception) tells you a bug exists. Breakpoint-driven analysis
at the assumption tells you why.

### Static analysis: audit the code path, not just the sink

Vulnerability research that begins at known dangerous sinks (`strcpy`, `memcpy`, `exec`) and
works backward misses entire classes of bugs where the dangerous operation is contextually
correct but the inputs are insufficiently validated earlier in the call chain.

From the TNEF research (MS06-003): the overflow was in a format parser, not a call to an obvious
unsafe function. Auditing the TNEF decoder required tracing the full data flow from the raw
attachment bytes through length extraction, allocation, and copy — identifying the length
arithmetic failure in the middle of the chain.

For automated static analysis: instrument the full call graph with taint tracking, not just a
sink-to-source backward scan.

### Fuzzing + source audit: complementary, not alternatives

Fuzzing finds crashes; source auditing finds root causes. Fuzzing without source audit leaves
you with a crash hash and no understanding of whether it is exploitable, what the root cause is,
or whether related bugs exist. Source audit without fuzzing misses bugs in code paths that are
not exercised by manual testing.

The correct workflow:
1. Source audit to identify high-risk code areas (complex parsers, type conversions, size
   arithmetic)
2. Targeted fuzzing of those paths with instrumentation to maximize coverage
3. For confirmed crashes: back to source to understand root cause and assess exploitability
4. Root cause analysis to find sibling bugs in the same pattern

---

## 10. Tooling and Technique Reference

| Category | Tool / Technique | Notes |
|----------|-----------------|-------|
| ActiveX fuzzing | Custom `IPersistPropertyBag` fuzzer | COM dispatch fuzzers (COMRaider) miss property bag interfaces; enumerate all interfaces before fuzzing |
| MSI analysis | Orca (Windows SDK) | SQL query of MSI tables; inspect CustomAction, LockPermissions, ServiceInstall, File tables |
| JRE debugging | JSwat | Breakpoint-based analysis of JVM internals; essential for authority component research |
| Kernel debugging | WinDbg + kernel dump analysis | IOCTL handler fuzzing + crash analysis |
| AML analysis | ACPI CA (Intel ACPI Component Architecture) | Decompile AML → ASL; recompile and flash modified BIOS |
| Firmware extraction | Physical BIOS flash read + `strings`/hex analysis | Foundation for ACPI and option ROM research |
| Exploit development | Heap spray, CVT read primitive, function pointer overwrite | JRE TrueType exploitation chain |
| NTLM capture | Unsigned Java applet + localhost HTTP server | No disk access required; works via Local Intranet zone trust |
| Coordinated disclosure | 90-day standard (Google Project Zero codified this after NGS era) | NGS practice: withhold technical details until patch is deployed |

---

## 11. 2024–2026 Currency Layer

The doc above is anchored on Heasman's 2005–2018 NGS/DocuSign-era output, which is the
load-bearing body of work that defines the methodology. This section deepens with the public
trail since the doc was authored — both Heasman's direct voice where it exists, and the broader
candidate-point-auditing tradition as it has matured through 2024–2026.

### 11.1 Heasman's role transition and current public posture

Heasman joined Proof (formerly Notarize) as Chief Information Security Officer in summer 2024
after five years as CISO at Chegg and five years as Deputy CISO at DocuSign. Proof's
announcement frames the role as overseeing the information security program and serving as
"the voice of the customer on security" for clients — a CISO posture rather than a research
posture (Proof, [Proof Welcomes John Heasman as Chief Information Security Officer](https://www.proof.com/blog/john-heasman-chief-information-security-officer)).

The most substantive recent public artifact is the **BSides Knoxville 2024 talk "Doing More in
AppSec by Doing Less"** ([sched listing](https://bsidesknoxville2024.sched.com/), [tl;dr sec
#266 coverage](https://tldrsec.com/p/tldr-sec-266), [LinkedIn re-share](https://www.linkedin.com/posts/john-heasman_john-heasman-doing-more-in-appsec-by-doing-activity-7288956268545769472-BCQ0)).
The talk's centerpiece is what Section 8 of this doc already captures as the
"True Positive Process" — and tl;dr sec's writeup preserves the surviving direct quote that
anchors the doctrine:

> "If everything is a priority, nothing is a priority."

The six-step recipe surfaced in the 2024 talk is byte-identical in shape to the BSides
methodology summarized in Section 8 (collect TPs → root-cause with engineering → abstract to
anti-pattern → prioritize by prevalence → fix → eliminate the class structurally). The 2024
talk frames it as an opinionated tour through application inventory, training, threat modeling,
SAST, DAST, and bug bounty — i.e. Heasman's mature stance on **the entire AppSec program
function**, not a research deep-dive. That this same methodology survives intact across the
Chegg → Proof transition is evidence that it is not a per-organization heuristic but a
generalizable program-design principle. See `[[reference-appsec-program-building]]` for the
program-building lineage that this doctrine sits inside.

### 11.2 The 2024–2026 AppSec context: AI-assisted code review, AI risk management, SBOM mandates

The methodology Heasman articulates above predates the 2024–2026 shifts but does not become
obsolete; if anything, the True Positive Process becomes more load-bearing as the volume of
LLM-generated findings rises. Four currency notes:

**AI-assisted code review and the "false sense of security" failure mode.** Multiple
peer-reviewed studies from 2024–2025 document that LLM-generated code contains substantially
more vulnerabilities than human-written code (the Veracode 2025 GenAI Code Security Report
reports a ~2.74× factor, with ~45% of AI-generated samples carrying OWASP Top 10 issues; a
GitHub Copilot security analysis found ~40% of generated programs contained vulnerabilities)
([CSA — Understanding Security Risks in AI-Generated Code](https://cloudsecurityalliance.org/blog/2025/07/09/understanding-security-risks-in-ai-generated-code),
[SoftwareSeni summary](https://www.softwareseni.com/ai-generated-code-security-risks-why-vulnerabilities-increase-2-74x-and-how-to-prevent-them/)).
Iterative AI code generation degrades further with each prompt cycle — one IEEE-ISTAS 2025
paper documents a 37.6% increase in critical vulnerabilities after five iterations
([arXiv 2506.11022](https://arxiv.org/html/2506.11022v2)). The corresponding failure mode in
user perception is well-documented: 81.9% of developers trust LLM-generated code to some
degree, and participants using AI assistants rate their insecure solutions as secure. This is
the AppSec inverse of Heasman's first-principles posture from Section 1 — pattern-matching
against trained distributions, not reasoning from root cause. The deepening implication:
**candidate-point auditing methodology is now load-bearing not just for human-written code but
for triaging the noisy output of LLM scanners**. See `[[reference-code-review-expertise]]` §9
for the deepened code-review-as-adversarial-collaboration framing.

**AppSec-as-AI-risk-management** is the emerging program shape circa 2025–2026: organizations
running two parallel security transformations (security FOR AI, and AI applied TO security
operations). The CISO-level framing is "AI Security Council" pulling from AppSec, data
science, compliance, and legal, with a five-level maturity model grounded in NIST AI RMF +
OWASP LLM Top 10 + CSA AISMM ([BeyondScale AI Security Maturity Model](https://beyondscale.tech/blog/ai-security-maturity-model-ciso-guide),
[Apiiro — Agentic AI Risk Management for CISOs](https://apiiro.com/blog/agentic-ai-risk-management-ciso-guide/)).
Heasman has not publicly authored material on this front; the candidate-point tradition's
contribution to this discipline is the insistence that **the AI agent runtime is a fresh
managed-to-native interface boundary** — the same kind of interface that Section 4 of this doc
calls out as the JRE's native attack surface "wearing a managed mask." Cross-link to
`[[reference-llm-agent-security]]` for the full agent-runtime expertise.

**SBOM mandates and the supply-chain dimension of AppSec.** EO 14028 (May 2021) accelerated the
SBOM requirement for federal software vendors; EO 14144 (January 2025) strengthened it with
third-party attestation; EO 14306 (June 2025) rescinded the enhanced attestation; OMB
Memorandum M-26-05 (January 2026) rescinded the standardized self-attestation form
requirements, shifting to per-agency risk-based assurance
([CISA — 2025 Minimum Elements for an SBOM](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom),
[Wiley — OMB Rescinds Secure Software Development Mandate](https://www.wiley.law/alert-OMB-Rescinds-Secure-Software-Development-Mandate-in-Favor-of-a-Risk-Based-Approach)).
In parallel, the **EU Cyber Resilience Act** (CRA) entered into force on 10 December 2024,
with main obligations applying from 11 December 2027 and vulnerability reporting from 11
September 2026 ([European Commission — Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act),
[OpenSSF — Global Alignment on SBOM Standards](https://openssf.org/blog/2025/10/22/sboms-in-the-era-of-the-cra-toward-a-unified-and-actionable-framework/)).
The operational impact on AppSec programs: the **pre-installation analysis discipline**
Section 2 calls out (MSI / Orca auditing of installers, ACL inspection of CustomAction tables)
generalizes directly to SBOM-driven analysis of third-party dependencies before deployment.
The attacker analyzes targets before engagement; the defender now has a regulatory mandate to
do the same.

### 11.3 DARPA AIxCC: candidate-point auditing at machine speed

The DARPA AI Cyber Challenge concluded at DEF CON 33 (8 August 2025). Team Atlanta (Georgia
Tech / KAIST / POSTECH / Samsung Research) won $4M with their **Atlantis** system — an
LLM-enhanced fuzzer. Trail of Bits' **Buttercup** took second with $3M; Theori took third
with $1.5M ([DARPA — AIxCC Final Competition Results](https://www.darpa.mil/news/2025/aixcc-results),
[aicyberchallenge.com — Final Competition Winners](https://aicyberchallenge.com/finals-winners-announcement/),
[Trail of Bits blog — Buttercup 2nd Place](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/)).

Key performance metrics from the scored round: teams identified **86%** of synthetic
vulnerabilities (up from 37% at semifinals), patched **68%** (up from 25%), and surfaced
**18 real non-synthetic vulnerabilities** (6 in C, 12 in Java) with 11 real patches. Four of
the seven CRSes were released open-source on competition day.

This is the canonical 2025 datapoint for the question Section 9 of this doc raises: does
fuzzing + source audit + root cause analysis scale when the fuzzer is LLM-enhanced and the
source audit is a structured reasoning loop? The AIxCC result says yes, for a narrow corpus
of well-formed C/Java codebases with synthetic injections plus real CVE backports. It does
NOT settle the broader question for production codebases with their own idiosyncratic
build systems, opaque framework reflection, and multi-language polyglot surfaces. See
`[[reference-vr-methodology]]` §13 for the deepened vulnerability-research-methodology
treatment of CRS-class systems.

### 11.4 The shift-left vs shift-right debate, updated

The 2025 consensus has converged on **"do both, calibrated"** rather than picking a side
([Upwind — Shift-Left vs Shift-Right Security: Finding the Right Balance](https://www.upwind.io/glossary/shift-left-vs-shift-right-security),
[Qable — Shift Left vs Shift Right Testing in 2025](https://www.qable.io/blog/shift-left-vs-shift-right-testing-2025)).
The pragmatic argument for shift-right has hardened: production observability surfaces
vulnerabilities that "actually matter" — the ones reachable under real load, real auth
context, real data — vs. the broader candidate set surfaced by shift-left scanners. Heasman's
True Positive Process is shift-left-flavored (root-cause-driven anti-pattern elimination at
the codebase layer) but it is not exclusionary; the "collect true positives" step explicitly
includes bug bounty and pen-test findings, which are shift-right artifacts. The doctrine
generalizes: **prioritize by prevalence, not by detection-time-left-or-right**.

The 2024–2026 datapoint that tilts the conversation: the mean time from CVE publication to
working exploit dropped from 56 days (2024) to 23 days (2025) to ~10 hours (2026)
([Hacker News — Your Purple Team Isn't Purple](https://thehackernews.com/2026/05/your-purple-team-isnt-purple-its-just.html)).
This compresses the shift-right window dramatically; production patching as the primary
defense increasingly is not viable. The corollary for AppSec programs: shift-left's
prevention-of-classes payoff per Section 8 of this doc has gone up, not down.

### 11.5 Firmware persistence research, 2023–2025

The firmware attack surface Section 3 of this doc maps (ACPI, PCI option ROMs, EFI/UEFI, SMM)
has produced two notable in-the-wild artifacts since the doc was authored:

- **BlackLotus** (publicly analyzed March 2023): first UEFI bootkit observed to bypass
  Secure Boot on fully patched Windows 11, sold on hacking forums from October 2022 at
  $5,000. Exploits CVE-2022-21894 (the "baton drop" Secure Boot bypass) to establish
  persistence; disables BitLocker, HVCI, Windows Defender ([ESET — BlackLotus UEFI bootkit:
  Myth confirmed](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/),
  [Binarly — The Untold Story of the BlackLotus UEFI Bootkit](https://www.binarly.io/blog/the-untold-story-of-the-blacklotus-uefi-bootkit)).
- **CosmicStrand** (Kaspersky GReAT, July 2022; ongoing analysis through 2024): UEFI firmware
  rootkit attributed to a Chinese-speaking threat actor, found in Gigabyte and ASUS H81
  chipset motherboard firmware images. Victims in China, Vietnam, Iran, Russia — narrowly
  targeted, no organizational pattern ([Kaspersky Securelist — CosmicStrand](https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/)).

ESET's Martin Smolár presented at RSA 2024 that "bootkits are no longer just a threat to
legacy systems but a real threat to the majority of modern UEFI firmware systems"
([ESET — Preparing for UEFI bootkits](https://www.eset.com/blog/en/business-topics/threat-landscape/uefi-bootkits-discovery/)).
This validates the Section 3 framing: the firmware layer is the persistence endgame, and the
mitigation chain (Secure Boot → measured boot → revocation) buys time but does not close the
attack surface. See `[[reference-firmware-embedded-security]]` for the deepened firmware/
embedded-security expertise.

### 11.6 Database security and the SQL-dialect-footgun tradition

*The Database Hacker's Handbook* (2005) catalog of platform-specific privilege escalation
primitives (Section 5 of this doc) has generalized into a broader practice of
**dialect-aware database security**: every database engine has a set of legitimate but
sharp-edged features (PostgreSQL `COPY TO/FROM PROGRAM`, MySQL `INTO OUTFILE`, SQL Server
`xp_cmdshell`, Oracle `UTL_HTTP`/`UTL_FILE`/Java stored procedures) that turn SQL injection
from an information-disclosure bug into OS code execution. The 2024–2026 currency is that
this catalog is being maintained as living documentation by the security-research community
rather than as a 2005-frozen snapshot. See `[[reference-sql-dialect-footguns]]` for the
shipped sibling expertise doc that extends the Heasman/Litchfield treatment to current
engine versions (PostgreSQL 16+, MySQL 8.0+, MS SQL Server 2022, Oracle 23ai).

### 11.7 Adversarial-collaboration discipline applied to security findings

The 2024–2026 maturation of "purple teaming" as a structural practice (red and blue working
side-by-side, pausing after each attack phase to share technique + detection logic) is a
direct organizational analog to the **Champion / Foil / Adjudicator** doctrine in
`[[reference-steelman-doctrine]]` §9. Heasman's True Positive Process implicitly assumes this
posture: the "partner with engineering to determine root causes" step succeeds only when
the AppSec function and engineering function genuinely engage with each other's framing of
the bug — engineering as Champion of the existing design, AppSec as Foil of the trust-
boundary claim, Adjudicator (the program manager) as the role that locks in the anti-pattern
verdict. When the relationship is adversarial-but-collaborative, the True Positive Process
produces structural fixes; when it is adversarial-only (AppSec ships tickets at engineering,
engineering closes them with minimum-viable patches), it produces whack-a-mole.

The cross-doc implication: **steelman doctrine is the missing organizational substrate that
makes the True Positive Process actually work**. AppSec teams that adopt the methodology
without the underlying collaboration discipline observe partial gains; teams that adopt both
observe class-elimination at scale.

### 11.8 What has NOT changed

The four pillars from Section 11.x (formerly Section 11, now renumbered) remain fully durable:
first-principles root cause analysis, full-stack scope, interface completeness, exploit chain
thinking. Heasman's 2024 BSides talk reinforces — does not retreat from — the
class-elimination-over-instance-fixing framing. The CVE catalog from 2005–2010 (CVE-2005-0227
PostgreSQL `LOAD`, MS06-003 Exchange TNEF, the OpenOffice metafile / RTF / hyperlink chain,
the JRE TrueType + URL-authority + JNLP-argument trio, the JRE-2018 DLL hijack at DocuSign)
still demonstrates every methodological commitment the doc canonizes. Section 12 below is the
unchanged summary of what defines staff-level adversarial AppSec work.

---

## 12. Summary: What Defines Staff-Level Adversarial AppSec Work

A staff-level adversarial security practitioner of Heasman's caliber is distinguished by:

1. **First-principles root cause analysis.** Every vulnerability is a consequence of a mechanism,
   not an accident. Identify the mechanism, find the full class of vulnerabilities that follows
   from it, and document the structural fix — not just the patch.

2. **Full-stack scope.** The attack surface extends from firmware (BIOS, EFI, option ROMs, SMM)
   through the OS kernel, through managed runtimes (JRE, CLR), through application frameworks,
   to the browser DOM. Security claims that assume a lower layer is trusted are claims that must
   be verified, not assumed.

3. **Interface completeness.** Always enumerate the full interface surface of a target before
   deciding what to test. The property bag gap is the canonical example: the tools covered 90%
   of the surface; the 10% they missed contained real vulnerabilities in widely deployed software.

4. **Exploit chain thinking.** Individual primitives (read, write, execute) are not exploits;
   they are components. A staff-level offensive practitioner maps primitive → geometry
   establishment → control flow hijack → payload delivery as a deliberate chain, and designs
   defenses that break the chain at its weakest link.

5. **Offensive methodology applied to defensive programs.** The True Positive Process is the
   offensive researcher's root-cause methodology — "find the structural cause, close the class" —
   applied to the defender's prioritization problem. The tools change; the thinking does not.

6. **Pre-deployment analysis as a security norm.** Attackers analyze targets before engaging.
   Defenders who analyze software before deploying it (installers, third-party packages, firmware
   updates) are operating at the attacker's pace instead of reacting to it.

7. **Disclosure discipline.** Technical publication of vulnerability details has consequences.
   The researcher who understands coordinated disclosure — timeline, patch availability, attacker
   patch-diffing window — operates as a responsible participant in the ecosystem, not just a
   trophy collector.
