# Shell, Argv, and Terminal-Escape Injection — Primitives and Defenses
## Synthesized from HD Moore, David Leadbeater, Alessio Della Libera, Etienne Stalmans, Eric Cornelissen, William Bowling, and Kurt Boberg

> **Researchers:**
> - **HD Moore** (@hdmoore) — Author of "Terminal Emulator Security Issues"
>   (2003, https://hdm.io/writing/termulation.txt), the canonical reference for
>   terminal-escape injection. Discovered CAN-2003-0020 (Apache error-log
>   escape injection) and CAN-2003-0063 (xterm window-title reporting → command
>   execution). Founded Metasploit (2003); currently at runZero.
> - **David Leadbeater** (@dgl, https://dgl.cx) — Audited modern terminal
>   emulators 2022-2023; published "ANSI Terminal security in 2023 and finding
>   10 CVEs" (https://dgl.cx/2023/09/ansi-terminal-security). CVEs:
>   2022-45872 iTerm2, 2022-44702 Windows Terminal/WSL, 2022-47583 mintty,
>   2022-45063 xterm, 2022-46387 + 2023-39150 ConEmu, 2022-4170 rxvt-unicode,
>   2022-23465 SwiftTerm, 2022-46663 less, 2023-39726 mintty. DEF CON
>   "Terminally Owned — 60 years of escaping." Also CVE-2025-48384 (git
>   arbitrary file write).
> - **Alessio Della Libera** (@dellalibera) — Snyk security researcher;
>   "Rediscovering argument injection when using VCS tools — git and
>   mercurial" (Snyk, August 2022,
>   https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/).
>   Disclosed CVE-2022-24433 (simple-git),
>   CVE-2022-25766 (ungit), CVE-2022-25648 (Ruby git gem), CVE-2022-25866
>   (czproject/git-php), CVE-2022-21187 (libvcs), CVE-2022-23915 (Weblate),
>   among 12+ language-spanning argv-injection CVEs across npm/PyPI/RubyGems/
>   Packagist/Go modules.
> - **Etienne Stalmans** (@_staaldraad, https://staaldraad.github.io) — Heroku
>   platform security engineer; "Argument injection and getting past
>   shellwords.escape" (Nov 2019); CVE-2019-13139 Docker build code execution;
>   Polycom HDX RCE. Articulated that `Shellwords.escape` leaves `-` unescaped
>   because it "isn't typically seen as an injection character"
>   and is "pretty common in file names" — the canonical statement of why
>   argument injection is structurally separate from metacharacter injection.
> - **Eric Cornelissen** (https://ericcornelissen.dev, PhD CHAINS supply-chain
>   security) — Maintainer of `shescape`
>   (https://github.com/ericcornelissen/shescape); shipped 15 advisories
>   (escape bypasses, ReDoS, path disclosure; CVEs include CVE-2021-21384, 2022-24725,
>   2022-31179, 2022-31180, 2022-36064, 2022-25918, 2023-35931, 2023-40185,
>   2025-30222, 2026-32094). Operates the most disciplined public corpus of
>   shell-escape regressions; treats the library itself as a research artifact.
> - **William Bowling** (@vakzz, https://hackerone.com/vakzz) — Australian
>   bug-bounty researcher; disclosed argv-injection RCE in GitHub Enterprise
>   Server via `git` option injection (paid $20,000); GitLab "MoveIssue"
>   arbitrary-file-read → RCE chain (paid $20,000). Hacker101 talk
>   "The journey of finding and exploiting a bug in GitLab."
> - **Kurt Boberg** (@kurt-r2c) — Staff Security Researcher at Semgrep;
>   credited on CVE-2022-30123 (Rack `Lint`/`CommonLogger` terminal-escape
>   injection, CVSS 10.0, https://github.com/advisories/GHSA-wq4h-7r42-5hrr)
>   and CVE-2021-42740 (shell-quote regex character-class bug,
>   https://github.com/advisories/GHSA-g4rg-993r-mgx7). Author of the
>   `escapeshellcmd`-is-weak-sanitizer doctrine cited throughout this doc.
>
> Sources: hdm.io; dgl.cx; Snyk research blog; staaldraad.github.io;
> shescape GHSA advisories; HackerOne disclosures; GitHub Advisory Database;
> NVD; primary Phrack/Bugtraq archives; OWASP Command Injection Cheat Sheet.

---

## 1. Core Philosophy

### Shell injection is not one bug class — it is three

Most "shell injection" writeups conflate three distinct primitives with three
distinct root causes and three distinct defenses:

1. **Metacharacter injection** (CWE-78). Attacker supplies a string that
   contains shell-parser metacharacters (`;`, `|`, `&`, `` ` ``, `$()`, `<>`)
   and the host process either invokes a shell directly (`/bin/sh -c "$cmd"`)
   or invokes a function (`system`, `popen`, `os.system`, `child_process.exec`)
   that does so implicitly. The shell parser tokenizes the metachars as
   command separators or substitution operators and executes attacker-chosen
   programs. Defense: do not pass user input through a shell parser.

2. **Argument injection** (CWE-88). The host process invokes a target binary
   directly via `execve`/`spawn` with an argv array, but attacker-controlled
   data sits in a positional slot the target binary interprets as a *flag*
   (e.g., `git --upload-pack=...`, `curl -o /etc/passwd`, `tar
   --checkpoint-action=exec=`). No shell is involved; the vulnerability is in
   the *target binary's* argv parsing, not in any quoting layer. Defense:
   `--` arg terminator + binary-specific allowlists.

3. **Terminal-escape injection** (CWE-150). Attacker-supplied data reaches a
   terminal (via logs, command output, error messages, filenames in `ls`)
   containing ANSI/VT100 control sequences (`ESC [`, OSC, DCS, CSI). The
   terminal emulator interprets them as state-changing commands — set window
   title, query cursor position, write to clipboard, define hyperlink, in
   some cases execute commands. The host process is not the target; the
   *operator viewing the host's output* is. Defense: structured logging,
   strip-or-escape `\x1b` at the output boundary.

A finding that treats these as the same bug class will misdiagnose every
fourth one. The `escapeshellcmd` family addresses class 1 and leaves
class 2 wide open (`feedback_escapeshellcmd_weak_sanitizer.md`). The
`shlex.quote` family addresses class 1 plus partial class 2 only when output
is reconcatenated for `/bin/sh -c`. No quoting library addresses class 3
because the bug is not in the host process at all.

### The architectural fix is "no shell parser between attacker bytes and execve"

The structurally correct posture is: never invoke a shell, never re-parse
user input as part of a command string, never log unescaped bytes to a
terminal. Concretely:

- Replace `system(cmd_string)` with `execve(absolute_path, [argv0, ...args])`.
- For unavoidable shell use (sudoers, pipelines, redirection), the entire
  command must be a literal in the source; user input goes through env
  vars passed to the shell, never interpolated.
- For logging, emit structured JSON / key-value records that are encoded by
  the log shipper rather than written to stdout for human reading. If a
  human-readable terminal output path exists, it must strip `\x1b` and OSC
  introducers at the boundary.

Quoting libraries (`shlex.quote`, `escapeshellarg`, `Shellwords.escape`,
`shescape`) are second-best fixes — they correctly defend against
metacharacter injection but require the developer to remember which class
they address and what their failure modes are. The volume of CVEs in
`shescape` alone (15 advisories in 5 years, all in a library *designed to
prevent shell injection*) is the working proof that this is true.

### The patch treadmill: blocklists are permanently broken

Any defense that enumerates dangerous characters is structurally doomed.
The reasons compound across the three classes:

- **Class 1** — POSIX shells accept input in multiple character encodings;
  any blocklist that filters `;` must also filter `\x3b`, `;`, `&#59;`
  in HTML contexts, percent-encoded `%3B` in URL contexts, and possibly
  UTF-8 confusables under some normalizations. Blocklists also miss
  `$IFS$9`, `${IFS}`, `\` line continuations, brace expansion `{a,b}`,
  arithmetic `$((...))`, ANSI-C `$'...'`, history `!!`, and shell-specific
  primitives that don't appear in the "classic" metacharacter list.

- **Class 2** — argument injection has no metacharacters at all. The
  attacker supplies `--upload-pack=evil` or `--checkpoint-action=exec=evil`
  using only `A-Za-z=-` and a few path characters. Every Shellwords-style
  filter that allows `-` (because `-` appears in filenames) is bypassable.
  Etienne Stalmans's canonical observation: "the one character that is not
  escaped, which allows us to gain argument injection is the `-`."

- **Class 3** — terminal-escape sequences are *defined* using only
  printable ASCII after the `ESC` byte (`\x1b`). A blocklist of "control
  characters" must include `\x1b` specifically and must understand the
  variable-length grammar of CSI / OSC / DCS — including OSC 8 hyperlinks
  whose terminator can be either `BEL` or `ESC \`, OSC 52 clipboard writes,
  OSC 7 working-directory updates, DECRQSS query echoback, and dozens of
  vendor-specific extensions.

The architecturally sound fix is always **allowlist**: known-safe character
set, known-safe binaries, known-safe argv positions, known-safe log
encodings.

---

## 2. Metacharacter Injection (CWE-78)

### The POSIX-shell parsing pipeline

`/bin/sh -c "$cmd"` runs the bytes of `$cmd` through the shell's parser
before they ever reach `execve`. The parser stages, in order:

1. **Tokenization** — split on unquoted whitespace, identify operators
   `; & | && || << >> ( )`, comments `#`, redirections.
2. **Alias expansion** — interactive shells only (mostly irrelevant for
   web exploitation).
3. **Brace expansion** — `{a,b,c}` → `a b c`.
4. **Tilde expansion** — `~user` → `/home/user`.
5. **Parameter / variable expansion** — `$VAR`, `${VAR}`, `${VAR:-default}`.
6. **Command substitution** — `` `cmd` ``, `$(cmd)` — *executes* the inner
   command and inlines its output. This is one of the canonical injection
   sinks: a single `` `id` `` is an unauthenticated RCE primitive.
7. **Arithmetic expansion** — `$((1+1))`. Can reach `set -e` failures and
   side effects via crafted expressions.
8. **Word splitting on `$IFS`** — by default space/tab/newline; controllable
   via `IFS=...`.
9. **Pathname expansion (globbing)** — `*`, `?`, `[abc]`.
10. **Quote removal** — final pass before `execve`.

Injection points exist at every stage. The classic injection — appending
`; id` to a vulnerable parameter — exploits stage 1 (tokenization). The
backtick-in-shell-quote bug (Kurt's CVE-2021-42740) exploits stage 6.
Brace-expansion bypasses of WAF rules exploit stage 3. `$IFS` whitespace
bypasses on filters that strip spaces exploit stage 8.

### Bash vs dash vs ash vs ksh vs zsh divergence

POSIX `sh` is not a single language. Concrete divergences that matter for
both exploitation and defense:

- **Process substitution `<(cmd)`** — bash, zsh, and ksh (where it
  originated). Not in POSIX dash (Debian/Ubuntu `/bin/sh`) or busybox ash
  (Alpine).
- **`{a,b}` brace expansion** — bash, zsh, ksh. Not in dash. Bypass
  implication: a regex filter that disallows `;` and `|` may allow a
  bash payload of `{cat,/etc/passwd}` that splits into argv via brace
  expansion + IFS.
- **`[[ ... ]]` test command** — bash/ksh/zsh. Dash uses `[ ... ]` only.
- **`$'...'` ANSI-C quoting** — bash/ksh/zsh. Dash POSIX-conforming and
  does not. Implication: `$'\x3b'` is a portable way to inject a semicolon
  past a literal-character filter, but only on shells that support it.
- **`((expr))` C-style arithmetic** — bash/ksh/zsh.
- **History expansion `!!` `!cmd`** — bash interactive only by default;
  irrelevant for most server-side exploitation.
- **`shopt -s globstar` `**` recursive glob** — bash 4+, zsh. Not POSIX.

Containers shipping `/bin/sh -> dash` (Debian-slim, Ubuntu-slim) and
`/bin/sh -> ash` (Alpine) are *more* restrictive than the bash assumed by
most CTF writeups. A bash-specific payload may simply fail on Alpine.
Conversely, code that invokes `bash -c` explicitly even when the system
shell is dash widens the attack surface back to bash semantics.

### cmd.exe and PowerShell quoting models

The Windows shells are not POSIX-compatible and have separate, frequently
confused, quoting rules.

**cmd.exe**:
- Metacharacters: `^ & | < > ( ) " %`.
- `^` is the escape character (not `\`).
- `&&`, `||`, `&` chain commands.
- `%VAR%` and `!VAR!` (delayed expansion) interpolate environment.
- Backslash is *not* an escape — it's a path separator. `"a\"b"` does
  not escape the inner quote in cmd.exe semantics.
- Critically: **the argv parsing rules for `CommandLineToArgvW`** differ
  from cmd.exe's own parsing. The C runtime parses argv from a single
  command-line string, with backslash-quote rules that are surprising
  enough to have produced a class of "argv injection" bugs (see Section 3).

**PowerShell**:
- Metacharacters: `; & | $ ( ) ` ' " #`.
- `;` separates commands (unlike cmd.exe where `;` is literal).
- `$()` is subexpression evaluation, like POSIX `$(...)`.
- `Invoke-Expression` (`iex`) is the canonical eval sink — equivalent to
  `eval` in JS or Python's `exec`. Any path from user input to `iex` is
  RCE.
- Backtick `` ` `` is the line continuation and escape character — NOT a
  command-substitution operator. This is a frequent confusion: `` `cmd` ``
  in PowerShell does nothing useful, but `$(cmd)` is the RCE primitive.
- ANSI escape sequences emit via `` `e `` (PS 6+) or `[char]27`.

### Why naive blocklists fail (cross-cutting)

Concrete bypasses against typical "remove `; & |`" filters:

```bash
# Subshell command substitution — no metachars from the blocklist
$(id)
`id`

# Brace expansion (bash/ksh/zsh)
{cat,/etc/passwd}

# $IFS whitespace bypass when space is filtered
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd

# ANSI-C quoting
$'\x3b id'

# Variable indirection
a=id;$a              # ; is filtered? try newline
a=id
$a

# Line continuation
ls \
/etc

# String concatenation
'l''s' '/e''tc'

# Globbing if files are partially known
/???/p?sswd
/usr/bin/c?t /etc/p?sswd

# Environment via PATH manipulation
PATH=/tmp:$PATH evil

# Tilde expansion
ls ~root
```

The space-bypass class deserves particular attention. Many CTF/training
filters strip all whitespace, expecting that to neutralize arguments.
`$IFS`, `{cmd,arg}` (brace-expansion auto-IFS), and `<<<` here-strings
all defeat this.

### Encoding-confusion bypasses

When user input passes through a decoding layer before reaching the shell,
the layer's encoding becomes a metacharacter substrate. Examples:

- **URL decoding**: `%3B` → `;` in any framework that URL-decodes path or
  query parameters. A filter that rejects `;` in the raw request body but
  the application decodes after filtering is bypassable.
- **HTML entity decoding**: `&#59;` → `;` when input passes through a
  template engine before reaching the shell.
- **Base64 indirection**: `echo BASE64 | base64 -d | sh` — the decoded
  payload is invisible to filters that only see the encoded form.
- **UTF-8 overlongs**: historically `0xC0 0xBB` could decode to `;` in
  loose UTF-8 implementations; modern decoders reject overlongs, but the
  underlying confusion still appears in non-UTF-8-aware filters that
  process raw bytes.

### Worked examples (the bug class in four languages)

**Python — the canonical sink-cluster**:

```python
# VULNERABLE — shell=True interpolation
import subprocess
def lookup(host):
    subprocess.run(f"dig {host}", shell=True)  # CWE-78
    subprocess.call(["sh", "-c", f"dig {host}"])  # equivalent
    import os
    os.system(f"dig {host}")  # equivalent

# SAFE — no shell parser; host is argv[1]
subprocess.run(["dig", host], shell=False, check=True)
```

The `shell=True` flag in `subprocess` is the central footgun. Python's
own `subprocess` docs caution against it explicitly — but legacy code
that uses `os.system` and `os.popen` is implicitly `shell=True`. Tellingly,
`shlex.quote` is a Python stdlib function specifically to make `shell=True`
slightly less dangerous; its existence is an admission that the API is
not safe by default.

**Node.js**:

```javascript
// VULNERABLE — child_process.exec spawns sh -c
const { exec } = require('child_process');
exec(`ping -c 4 ${host}`, callback);   // CWE-78

// SAFE — execFile / spawn with argv array
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', host], callback);
```

The Node `child_process` API has the same shape as Python's `subprocess`:
`exec` is shell-with-string (sh -c), `execFile`/`spawn` are direct
`execve` with argv arrays. The `child_process.exec` API is a frequent
finding in static analysis — particularly when developers reach for it
because the argv form requires splitting a command string they have as
a literal.

**Ruby**:

```ruby
# VULNERABLE — backtick / %x{...} / Kernel#system with single string
output = `dig #{host}`            # CWE-78
output = %x{dig #{host}}          # equivalent
system("dig #{host}")             # CWE-78 — sh -c invoked

# SAFE — system / exec with array form
system("dig", host)               # argv-array; no shell
Open3.capture3("dig", host)       # same
```

Ruby's `system(cmd)` invokes `sh -c` when given a single string argument,
but invokes `execve` directly when given an argv array. The "argv array
when length > 1" rule is non-obvious; a developer rewriting `system("dig
#{host}")` as `system("dig", host)` is making a security-significant
change that does not look like one in code review.

**PHP**:

```php
// VULNERABLE — shell parser invoked
shell_exec("dig $host");          // CWE-78
exec("dig $host");                // same
system("dig $host");              // same
passthru("dig $host");            // same
$h = popen("dig $host", "r");     // same
$fh = `dig $host`;                // backtick — same

// "PARTIALLY SAFE" — escapeshellarg handles class 1
exec("dig " . escapeshellarg($host));  // class 1 ok, but no class 2
                                        // protection — see Section 3

// SAFE — proc_open with argv array (PHP 7.4+)
$descriptors = [0 => ["pipe","r"], 1 => ["pipe","w"]];
$proc = proc_open(["dig", $host], $descriptors, $pipes);
```

PHP has no escape-by-default API. Every shell-invoking function takes a
string and invokes `sh -c`. The `escapeshellarg`/`escapeshellcmd` family
is the historical defense, and the distinction between them is critical
and rarely understood — see Section 3.

---

## 3. Argument Injection (`escapeshellcmd` is not `escapeshellarg`) (CWE-88)

### The distinction: metacharacter escaping vs argument-boundary preservation

`escapeshellcmd` and `escapeshellarg` solve different problems despite
nearly identical names:

- **`escapeshellcmd($s)`** escapes shell metacharacters (`#&;` `` ` ``
  `|` `*` `?` `~` `<` `>` `^` `(` `)` `[` `]` `{` `}` `$` `\` `\x0A`
  `\xFF`) by prefixing with `\`. The output is safe to pass through a
  shell parser **as a complete command** without injection — but
  whitespace is *not* escaped, so the attacker can still introduce
  additional arguments to the binary being invoked.

- **`escapeshellarg($s)`** wraps the entire string in single quotes and
  escapes embedded single quotes (`'` → `'\''`). The output is a *single
  argv slot* — the binary receives the entire string as one argument
  regardless of whitespace.

The PHP manual is explicit about this distinction; the failure mode is
that developers reach for the function whose name pattern-matches their
mental model of "escaping a command" and end up with `escapeshellcmd`
when they needed `escapeshellarg`.

**CVE-2022-24828 (composer)** is a demonstration of why this matters. An
attacker who controls a Git or Mercurial repository listed by URL in a
project's `composer.json` can use crafted branch names to run commands
when `composer update` runs; the `--` delimiter used against a similar
issue the year before was not available on that path, and the fix rejects
branch names that start with a dash. **The shell did exactly what it
was supposed to do.** The injection is in the argv parsing of the VCS
binary, not in the shell's parsing of the command line.

This is a documented lesson from production static-analysis workflow tuning: do
**not** treat the presence of `escapeshellcmd` on a dataflow path as
exculpatory. Label it "weak sanitizer — argv injection bypasses" so
findings stay above the FP-suppression threshold. The mistake the
exploitability rescorer made on the composer benchmark was treating
`escapeshellcmd` as a strong sanitizer; one-line catalog fix.

### The `--` arg terminator and which utilities honor it

POSIX `getopt` defines `--` as a sentinel terminating option processing:
arguments after `--` are positional, never flags. **This is the cheapest
class-2 fix in the language.** It works for any binary whose option
parser respects POSIX `getopt` conventions, which is most of them.

The recipe:

```bash
# VULNERABLE — $URL controlled, attacker sets --upload-pack=evil
git clone "$URL" "$DIR"

# SAFE — -- terminates option processing
git clone -- "$URL" "$DIR"
```

But not every utility honors `--` the same way:

| Binary | `--` honored | Notes |
|---|:---:|---|
| git (subcommands) | yes (mostly) | Per-subcommand; `git ls-remote` accepts; `git push` did not always — verify per version |
| ssh | partial | Honored for hostname in some versions; ProxyCommand is a separate vector that runs *before* argv parsing |
| scp | partial | Filename-as-flag class — see below |
| rsync | yes | `-e` (remote-shell) is a separate hazard |
| curl | yes | `-K` config-file flag also a hazard |
| wget | yes | `-i` input-from-file similarly hazardous |
| find | yes | `-exec`, `-execdir`, `-fprintf` are pre-`--` execution primitives |
| rm | yes | Filename-as-flag class — see below |
| tar | yes | `--checkpoint-action=exec=` is the canonical post-`--`-misuse case |
| sed | partial | `-e`/`-f` interaction with `--` is version-dependent |
| awk | yes | `-f program-file` is the hazard before `--` |
| perl | NO | `-e` `-M` etc. parse aggressively; argument injection in scripts that pass user input to `perl` is endemic |

The "filename-as-flag" class deserves separate treatment: when the
attacker controls a file's *name* (not its content), and that name
becomes a positional argument to a binary, names starting with `-` are
flags by default. The canonical example is `rm` on user-uploaded
content:

```bash
# VULNERABLE — attacker creates file named "--no-preserve-root"
rm *

# SAFE
rm -- *
rm ./*
```

`find -print0 | xargs -0 ...` chains amplify this — `xargs` re-parses
the names from stdin and applies them as argv, and again, names starting
with `-` are flags.

### Tool-specific argv-injection corpus

A non-exhaustive list of binaries with known dangerous flags. When user
input may land in argv to any of these without `--`, treat as RCE
candidate:

**`git`** (Alessio Della Libera's research corpus):

- `--upload-pack=<cmd>` (`ls-remote`, `fetch`, `pull`, `clone`) —
  executes `<cmd>` server-side during the protocol exchange. The cmd
  shell-parses, so this is *both* class 2 and class 1.
- `--receive-pack=<cmd>` — same for `push`.
- `--config <key>=<val>` — sets transient config that controls behavior
  including `core.sshCommand`, `core.gitProxy`, `protocol.allow`,
  `uploadpack.allowFilter`. Setting `core.sshCommand=evil` and then
  attempting a clone over ssh is RCE.
- `--exec=<cmd>` (`upload-pack`/`receive-pack`/`http-fetch`) — direct
  execution primitive.
- `--ext::<cmd>` URL — git supports `ext::` URLs that execute external
  commands as protocol handlers.
- `--system`/`--global` config edits — write to global config.

**`mercurial` (hg)** — even more dangerous than git per Della Libera:

- `--config alias.<cmd>=!<shell-command>` — defines a shell alias.
  `hg --config alias.init='!touch HELLO' init` runs `touch HELLO`.
- `--config hooks.<event>=<cmd>` — registers a hook that runs on the
  named event. `hg --config hooks.pre-init='touch HELLO' init` runs
  `touch HELLO`.
- Critically: *one* attacker-controlled argument is sufficient for
  RCE in hg, vs. git's requirement for multiple controlled args.

**`ssh`/`scp`**:

- `-o ProxyCommand=<cmd>` — ssh executes `<cmd>` to set up the
  connection. Hostname injection that adds `-o ProxyCommand=...` is RCE.
- `-i <keyfile>` — file read; can be combined with key-confusion.
- `-F <configfile>` — load config from attacker-chosen file.
- `-J <jumphost>` — jump-host hostname spec is parsed before connection.

**`curl`/`wget`**:

- `curl -K <file>` — read config from file (which itself can contain
  any flag); attacker-controlled file is RCE.
- `curl --output <file>` — write to filesystem.
- `curl -F @<file>` — read file as form data.
- `wget --use-askpass=<cmd>` — execute `<cmd>` to get password.
- `wget --post-file=<file>` / `wget -i <file>` — file read.

**`find`**:

- `-exec <cmd> {} \;` — direct command execution. Argument injection
  into a `find` invocation that *constructs* an `-exec` is the
  pre-existing primitive.
- `-fprintf <file> <format>` — write to attacker-chosen file.
- `-newer <ref>` — file read.

**`rsync`**:

- `--rsync-path=<cmd>` — server-side command. With `-e <ssh-cmd>` this
  composes into RCE.
- `-e <ssh-spec>` — remote-shell command. Separately, rsyncd before 3.1.3
  did not prevent multiple `--protect-args` uses, bypassing its
  argument-sanitization (CVE-2018-5764).

**`tar`**:

- `--checkpoint=<n> --checkpoint-action=exec=<cmd>` — executes `<cmd>`
  every n records during extraction. Etienne Stalmans's canonical
  Shellwords.escape bypass uses exactly this chain.
- `--use-compress-program=<cmd>` — execute compressor.
- `--rmt-command=<cmd>` — execute remote-tape command.
- `-T <listfile>` / `--files-from=<file>` — read file list from file.

The taxonomy: any binary with a `--<flag>=<command>` or `--<flag>=<file>`
construction is potentially a class-2 RCE primitive when user input
reaches argv pre-`--`.

### shescape and shell-quote: when the sanitizer is the bug

Eric Cornelissen's `shescape` library and Charles Lehner's `shell-quote`
npm package both attempt to be the canonical Node.js shell-escape
library. Both have accumulated CVEs at a rate that demonstrates the
underlying difficulty of the problem.

**CVE-2021-42740 (shell-quote, credit kurt-r2c + jwilk + levpachmanov)**:

The shell-quote package's regex for stripping Windows drive letters
used `[A-z]` (range from `A` to lowercase `z`). The ASCII range from
`Z` (0x5A) to `a` (0x61) contains `[ \ ] ^ _ ` ` `` — including the
backtick (0x60), which is the command-substitution operator in POSIX
shells. An input like `` C`id`:\foo `` would not be properly quoted; if
the output was concatenated into `sh -c "..."`, the backtick triggered
command substitution. The fix was `[A-Za-z]`.

The bug is illustrative: a one-character mistake in a regex character
class, in a library whose entire purpose is shell escaping, produced a
CVSS 9.8 RCE primitive. The fix is one character. **Trust placed in
escape libraries should be proportional to the audit depth of their
character classes.**

**CVE-2022-31180 (shescape, credit kurt-r2c)** and the broader shescape
CVE sequence:

Shescape has shipped 15 advisories across 5 years (2021-2026,
https://github.com/ericcornelissen/shescape/blob/main/SECURITY.md). The
recurring themes:

- **CVE-2022-31180**: insufficient escaping of whitespace in
  bash/dash/zsh/PowerShell when `interpolation: true`; attackers
  introduce commands after specific whitespace characters.
- **CVE-2022-31179**: insufficient escaping of line feeds for CMD.
- **CVE-2022-36064 / CVE-2022-25918**: inefficient regular expression
  complexity (ReDoS).
- **CVE-2023-35931 / CVE-2023-40185**: environment-variable exposure on
  Windows with CMD; Windows escaping bypassable in threaded context.
- **CVE-2025-30222**: potential environment variable exposure on Windows
  with CMD.
- **CVE-2026-32094**: glob bracket-expansion bypass on Bash/BusyBox/Dash.
- **CVE-2026-30916** (advisory later withdrawn): possible misidentification
  of shell due to link chains.

The lesson: even a competently-maintained shell-escape library
(Cornelissen is a PhD researcher in supply-chain security and operates
the most disciplined public regression corpus of any escape library)
accumulates bypasses at a rate that exceeds the speed of any single
auditor. The volume is *the* working evidence for "don't escape, use
argv".

### William Bowling's GitHub Enterprise argv injection

Bowling's GitHub Enterprise Server disclosure (2020) injected malicious
arguments via git command options, which could let an attacker overwrite
arbitrary files and potentially execute arbitrary commands. Exploitation
required repository access, and GitHub said a CSRF protection mechanism
blocked a practical attack path. Paid $20,000 by GitHub; patched in
GitHub Enterprise 2.21.4 (August 2020).

### Kurt's CVE-2021-42740 in detail

The shell-quote bug ([GHSA-g4rg-993r-mgx7](https://github.com/advisories/GHSA-g4rg-993r-mgx7))
is worth dissecting because it demonstrates how research-grade
shell-injection findings look in 2021:

1. **Audit target**: shell-quote was the canonical npm package for the
   problem space. Audit attention
   was high.
2. **Bug location**: a regex for Windows drive-letter detection inside
   the exported `quote()` function.
3. **Primitive**: `[A-z]` instead of `[A-Za-z]` in the character class.
   The mistake is so common in lazy regexes that linters like ESLint
   do not flag it.
4. **Reachability**: any code that passed `quote()` output to a real
   shell (e.g. `exec()`) as a quoted argument.
5. **Impact**: when the quoted output was reconcatenated
   into a shell command (which is the *whole point* of a shell-quote
   library), the backtick reached the shell as a metacharacter.
6. **Fix**: one character change.

The story line is the same as composer/CVE-2022-24828: the sanitizer is
the bug. Audit checklists for "we use shell-quote" should not stop at
"is shell-quote used"; they should continue to "which shell-quote
version" (1.7.3 fixed it).

---

## 4. Terminal-Escape Injection (CWE-150)

### The primitive

ANSI escape sequences (ISO 6429 / ECMA-48 / VT100 family) are
attacker-controllable strings that command the terminal emulator to
perform state-changing operations. The basic structure:

```
ESC [ <params> <intermediate> <final>    -- CSI (Control Sequence Introducer)
ESC ] <Ps> ; <Pt> BEL                    -- OSC (Operating System Command)
ESC ] <Ps> ; <Pt> ESC \                  -- OSC, ST-terminated
ESC P <params> ; <data> ESC \            -- DCS (Device Control String)
ESC X ... ESC \                          -- SOS
ESC ^ ... ESC \                          -- PM
ESC _ ... ESC \                          -- APC
```

The escape character is `\x1b` (octal 033, ASCII 27). CSI introducers
(`ESC [`) drive cursor movement, color, mode setting. OSC (`ESC ]`)
drives "operating system" commands — window title, clipboard, working
directory, hyperlinks. DCS drives device-specific commands; in
practice, most exploitation flows through OSC because of the
attacker-friendly state-change scope.

The vulnerable pattern: user-controlled data reaches a terminal output
path (logs, error messages, HTTP response bodies viewed in a curl-like
client, filenames in `ls`, exception traces, command output) without
having `\x1b` stripped or encoded. The terminal interprets the
sequences.

### HD Moore's foundational research (2003)

HD Moore's "Terminal Emulator Security Issues" paper
(https://hdm.io/writing/termulation.txt) is the canonical reference.
Key attack classes he identified:

1. **Escape-sequence injection via syslog**. Apache error logs and some
   syslog daemons (msyslog, syslog-ng, some commercial UNIX loggers)
   passed remote data directly to terminal output without sanitization. `tail -f
   /var/log/apache/error_log` viewed in xterm became an exploitable
   path. CAN-2003-0020.

2. **Screen dumping**. Eterm and rxvt supported escape sequences to
   write the terminal contents to a file. Attacker writes the escape
   sequence to a log → admin tails the log → terminal writes
   `~/.ssh/authorized_keys` (or similar) with attacker-controlled
   content.

3. **Window title reporting**. xterm and most descendants supported
   setting the window title via OSC 0 / OSC 2, *and* querying it via a
   separate escape sequence that wrote the title back into the
   terminal's input stream. If the title is attacker-controlled, the
   query-response writes attacker bytes into the user's command-line
   buffer. Combined with hidden text attributes (color = background,
   blink suppression), attacker bytes are invisible until the user
   presses Enter. CAN-2003-0063 (xterm).

4. **DoS via malformed sequences**. Crashed or hung the terminal,
   preventing log inspection during compromise.

5. **Menubar manipulation** (rxvt, aterm). Attacker-controlled menu
   modifications that executed commands on click.

Moore's prescient framing: these are *features* of terminal emulators,
not bugs. Their existence is the vulnerability. Mitigations require
disabling the features or filtering output at the boundary.

### David Leadbeater's 2023 audit and the 10 CVEs

20 years after Moore, David Leadbeater audited modern terminal emulators
(https://dgl.cx/2023/09/ansi-terminal-security) and found 10 CVEs across
iTerm2, Windows Terminal, mintty, xterm, ConEmu, rxvt-unicode, SwiftTerm,
and `less`. The findings cluster:

- **DECRQSS echoback (CVE-2022-45872 iTerm2, CVE-2022-47583 mintty,
  CVE-2022-23465 SwiftTerm)** — the DECRQSS
  query (`ESC P $ q ... ESC \`) asks the terminal for its current
  attribute state. The terminal *echoes back* a response on stdin —
  which is what makes this an injection primitive. If the attacker
  controls part of the terminal state being queried, they control part
  of the response, which lands on the user's command line.

- **Window title reporting (CVE-2022-46387, CVE-2023-39150 ConEmu)** —
  the 2023 incarnation of Moore's 2003 finding. ConEmu had title
  reporting enabled by default in 2022; even modern terminals still
  ship the feature in some configurations.

- **OSC 8 hyperlink injection (CVE-2022-46663 `less`)** — OSC 8 defines
  hyperlinks in terminal output. `less` failed to terminate hyperlink
  ranges properly; attacker-controlled bytes could make subsequent
  terminal output into one giant clickable link with an attacker-chosen
  target.

- **OSC 7 working-directory updates** — Apple Terminal performed DNS
  lookups on attacker-controlled OSC 7 strings, leaking information.

- **OSC 50 font query (CVE-2022-45063 xterm + Zsh vi-mode; CVE-2023-39726
  mintty)** — xterm's
  font-query response interacted with Zsh's vi-mode keybindings to
  execute commands.

- **Working-directory command injection (CVE-2022-44702 Windows
  Terminal + WSL)** — duplicating a tab read the "working directory"
  set via OSC 9;9 in WSL; that string was used in command construction
  without validation, leading to command execution on tab-duplicate.

- **Background extension Perl eval (CVE-2022-4170 rxvt-unicode)** — the
  background-image extension evaluated untrusted input as Perl.

The common pattern across the 2023 finds and the 2003 finds:
**control-character-in-reply**. The VT100 protocol allows the terminal
to respond to queries, and well-formed responses are limited to a
specific syntax — but implementations frequently accepted control
characters (`\r`, `\n`, `\t`) in the params, which the receiving
process treated as command separators. The fix in most cases was
strict input validation on the *terminal*'s reply path; the underlying
attack surface remains.

### Kurt's CVE-2022-30123 (Rack Lint/CommonLogger)

[GHSA-wq4h-7r42-5hrr](https://github.com/advisories/GHSA-wq4h-7r42-5hrr)
— credited to kurt-r2c.

Rack is the canonical Ruby web-server interface. Two of its bundled
middlewares, `Rack::Lint` (validates application responses) and
`Rack::CommonLogger` (writes access logs in Apache common format),
wrote HTTP request and response data to `$stderr` (or a logger handle)
without filtering. Crafted requests with `\x1b[` in HTTP headers
caused terminal escape sequences to land in the log output.

If the operator viewing the log was using a vulnerable terminal — any
terminal vulnerable to title-injection, OSC-clipboard, or any of HD
Moore's class of attacks — the attacker could chain into command
execution. Rack rated this CVSS 10.0 because the exploitation path
spans an HTTP-only attacker → terminal emulator on the operator's
desktop → code execution as the operator.

The fix landed in Rack 2.0.9.1 / 2.1.4.1 / 2.2.3.1: filter or strip
control characters before writing to the log handle. This is the
*defensive* version of Moore's recommendation: do not transmit
unfiltered bytes to a terminal context.

### Why structured logging is the canonical fix

The naive log fix — strip `\x1b` — is correct but fragile. It fails
when:

- The log is consumed by `tail -f`, `journalctl`, or any tool that
  emits raw bytes to a terminal.
- Multi-step pipelines (rsyslog → fluentd → S3 → human download → less)
  introduce new opportunities for bytes to be re-rendered on a terminal.
- Application-level loggers wrap multiple sinks (file, stdout,
  CloudWatch); only one sink may sanitize.

Structured logging is the architectural answer. The log entry is a
JSON object; field values are escaped at JSON encoding time (`\x1b`
becomes ``); the log consumer chooses the rendering. If a human
ever views the entry in a terminal, the viewer (jq, structured
log-tail tools) is responsible for safe rendering — typically by HTML-
or JSON-escaping the value.

Concretely:

```ruby
# VULNERABLE — string interpolation into a stderr write
$stderr.puts "request from #{request.user_agent}"

# WEAK — strip \x1b at the boundary
$stderr.puts "request from #{request.user_agent.gsub(/\e/, '')}"

# CORRECT — structured logging
logger.info(event: "request", user_agent: request.user_agent)
# Output is JSON; \e in user_agent becomes  in the JSON-encoded value
```

The same pattern applies in every language. Python: stdlib `logging`
with python-json-logger's `JsonFormatter`. Node: `pino` or `bunyan`. Go: `slog` with
`JSONHandler`. Java: `logback` with `JsonEncoder`. The cost of moving
from string-format logging to structured logging is non-trivial in
codebases that print, but the security argument is structurally sound:
the encoding boundary lives in the log library, not in every callsite.

### iTerm2 / Windows Terminal / xterm divergence

For exploitation and detection purposes, the divergence in escape-
sequence handling across terminals is significant:

- **iTerm2** (macOS) — supports the largest set of "proprietary" escape
  codes (`iterm2.com/3.2/documentation-escape-codes.html`), including
  OSC 1337 for tab colors, OSC 52 clipboard, OSC 8 hyperlinks, OSC
  133 prompt marks. Has a "potentially insecure" mode that disables
  some features. CVE-2022-45872 demonstrated that even with hardening,
  DECRQSS could echo back attacker-controlled bytes.

- **Windows Terminal** — Microsoft's modern terminal; supports OSC 9;9
  (working directory) which was the substrate for CVE-2022-44702.
  Diverges from xterm on which control characters are accepted in
  replies.

- **xterm** — the historical reference implementation; defaults are
  cautious in modern versions but the codebase supports thousands of
  legacy sequences, many of which still bite (CVE-2022-45063 font query).

- **Terminal.app** (macOS native) — OSC 7 DNS lookup leak; otherwise
  relatively conservative.

- **PuTTY** — Windows; CyberArk's Eviatar Gerzi found rapid title-
  change DoS class. Conservative on OSC clipboard.

- **mintty** (Cygwin / Git for Windows default) — DECRQSS echoback
  CVE-2022-47583 and OSC 50 echoback CVE-2023-39726.

- **ConEmu** — title reporting enabled by default into 2022;
  CVE-2022-46387 and CVE-2023-39150.

- **`less`** (the pager) — CVE-2022-46663 OSC 8 termination bypass.
  Often the terminal *target* even when the actual emulator is
  hardened, because the pager re-emits sequences.

### Detection patterns (logs, code review)

When reviewing for terminal-escape injection:

```bash
# Logs that may contain unescaped \x1b
grep -P '\x1b\[' /var/log/*.log

# Source-code search: any logging call with user-controlled data
# Python
grep -rE 'log(ger)?\.(info|warn|error|debug)\(.*\+.*(request|user|input)' src/
# Node
grep -rE 'console\.(log|error|warn)\(.*\+.*(req\.|user|input)' src/
# Ruby
grep -rE 'logger\.(info|warn|error)\b.*#\{' src/

# Sinks that bypass structured loggers
grep -rE '(puts|print|printf|fprintf|stderr|stdout)' src/ | grep -i 'request\|user\|header'
```

The "found a log line that interpolates a header" finding is a class-3
TerminalEscapeInjection candidate when:

- The application receives untrusted bytes (HTTP headers, user-agent,
  request body, query parameters).
- Those bytes reach a string-format logger or print statement.
- The log is consumed in a terminal context (typically all access logs
  in development, often access logs in production via `kubectl logs`,
  `journalctl`, Docker logs).

The defense-grade fix is structured logging. The mitigation-grade fix
is strip-or-encode `\x1b` at the encoder. Either is correct; the
weakness of the latter is that it must be applied at every callsite.

---

## 5. Shell Escape Libraries as Attack Surface

### The meta-insight: when the sanitizer is the bug, defense in depth collapses

The CVE corpus across `shescape`, `shell-quote`, `Shellwords.escape`,
`escapeshellcmd`/`escapeshellarg`, and Python's `shlex.quote` demonstrates
a structural problem: shell escaping is *itself* a bug class. A library
that promises to make user input safe to pass to a shell takes on the
correctness obligation of the entire POSIX shell grammar — which the
shell implementations themselves diverge on.

The volume of CVEs is the evidence:

| Library | CVE count | Notes |
|---|---:|---|
| shescape | 15 advisories 2021-2026 | Cornelissen, the most disciplined of the lot |
| shell-quote (npm) | 1 major (2021-42740), several pre-disclosure | one-character regex bug |
| Shellwords.escape (Ruby) | informal "class 2 doesn't work" — Stalmans 2019 | structural limitation, no patch needed |
| Python shlex.quote | structural class-2 limitation; no critical bypasses | safer than most because it has narrow scope |
| PHP escapeshellarg | OK for class 1, NOT class 2 | naming-confusion with escapeshellcmd is the bug |
| PHP escapeshellcmd | dangerous; class-1 only; widely misused | |

The architectural recommendation is twofold:

1. **Prefer `execve` with argv array.** No shell, no escaping library,
   no bypass class. Use this whenever possible.

2. **If shell-with-string is unavoidable** (sudoers semantics,
   redirection, pipelines), structure as: the *command literal* in
   source, user input via env vars passed to the shell, env vars
   referenced inside the literal as `"$VAR"` quoted strings. The shell
   parser then has zero attacker-controlled bytes during parsing.

```python
# CORRECT — env-var indirection
subprocess.run(
    'echo "user is $USER_INPUT" >> /tmp/log',
    shell=True,
    env={'USER_INPUT': attacker_data}
)
# The shell sees the literal echo command; $USER_INPUT is dereferenced
# AFTER parsing, so the attacker-controlled bytes never reach the parser.
```

### Differential testing across libraries

Differential testing for
parsing-and-quoting libraries: generate identical inputs, feed them
through every quoting library (shescape, shell-quote, Shellwords.escape,
escapeshellarg, shlex.quote), and execute the resulting commands.
Inconsistencies between libraries are the most efficient bypass-
hunting heuristic.

### The "use exec-with-array, not shell-with-string" principle

In every language, the canonical safe pattern is the argv-array form
of `execve`:

```python
# Python
subprocess.run(["dig", host], shell=False, check=True)
```

```javascript
// Node.js
require('child_process').execFile('dig', [host], cb);
```

```ruby
# Ruby
system("dig", host)              # argv array → execve
Open3.capture3("dig", host)      # same
```

```php
// PHP — proc_open with array argv (PHP 7.4+)
proc_open(["dig", $host], $descriptors, $pipes);
```

```go
// Go
exec.Command("dig", host).Output()  // argv array, no shell
```

```java
// Java
new ProcessBuilder("dig", host).start();  // argv list
```

The argv-array pattern collapses class 1 entirely — there is no shell
parser. Class 2 (argv injection) is still possible if the attacker
controls a position that the target binary parses as a flag, but the
fix for class 2 is `--`, which is much cheaper than escaping.

### When you MUST use shell=True

Real cases where shell-with-string is necessary:

- Pipelines: `cat | grep | sort`. Argv-array doesn't compose these.
- Redirection: `echo > /tmp/file 2>&1`. Argv-array doesn't redirect.
- Subshell features: `()`, `{}`, `||`, `&&`.
- Wrapping: `sudo -u user sh -c '...'` (though `sudo -u user -- argv...`
  is usually preferable).

In all these cases, the discipline is the same: **the entire shell
expression is a literal in source code**. Attacker input never reaches
the shell parser. If user input must appear in the shell command, it
appears as `$ENVVAR` references inside the literal, with the env vars
populated by the caller.

```python
# CORRECT
subprocess.run(
    'cat "$INFILE" | grep "$PATTERN" | sort > "$OUTFILE"',
    shell=True,
    env={
        'INFILE': user_input_path,
        'PATTERN': user_input_pattern,
        'OUTFILE': user_input_output,
    }
)
```

The env-var-as-indirection pattern is the canonical defense when
shell-with-string is genuinely required. It is rare; most apparent
shell-pipeline needs are better expressed as multiple argv-array
invocations chained programmatically.

---

## 6. Detection Patterns (Semgrep / Static-Analysis Lens)

The Semgrep rule-authoring sibling doc (`semgrep_rule_authoring.md`)
covers rule mechanics; this section articulates *what to look for*.

### Sink catalog by language

**C / C++**:
- `system(char *)` — sh -c invocation; CWE-78.
- `popen(char *, char *)` — same.
- `execl`, `execlp`, `execle`, `execv`, `execvp`, `execve` — depends on
  whether argv0 is literal and whether subsequent args are literals.
  `execvp` is more dangerous than `execve` because PATH lookup happens.
- `wordexp(char *, ...)` — explicitly does shell expansion including
  command substitution; CVE-2014-7817 demonstrated arbitrary command
  execution.

**Python**:
- `os.system(str)`, `os.popen(str)` — sh -c invocation.
- `subprocess.{run,call,check_output,Popen}(... , shell=True)` — same.
- `subprocess.{run,call,check_output,Popen}([list], shell=False)` —
  SAFE for class 1, potentially class 2 if `list[0]` is user-controlled.
- `commands.getoutput` / `commands.getstatusoutput` (Python 2) — same.

**Node.js**:
- `child_process.exec(str, cb)` — sh -c.
- `child_process.execSync(str)` — sh -c synchronous.
- `child_process.spawn(cmd, args, { shell: true })` — sh -c when
  `shell: true`. Default `shell: false` is safe for class 1.
- `child_process.execFile(file, args, cb)` — direct execve.
- `process.binding('spawn_sync')` — bypassing the standard API.

**Java**:
- `Runtime.getRuntime().exec(String)` — single-string form parses with
  StringTokenizer (whitespace split, no shell). NOT shell injection
  but argv injection.
- `Runtime.getRuntime().exec(String[])` — direct argv.
- `new ProcessBuilder(List<String>)` — direct argv.
- `Runtime.exec("sh", "-c", cmd)` — explicit shell invocation; CWE-78.

**Ruby**:
- `system(str)`, `exec(str)`, `` `cmd` ``, `%x{cmd}`, `IO.popen(str)`
  — sh -c when given a single string.
- `system(cmd, *args)`, `exec(cmd, *args)` — argv form, safe.
- `Open3.capture3(str)` / `Open3.capture3(cmd, *args)` — same
  string-vs-args distinction.
- `Kernel.eval` / `instance_eval` — Ruby eval, not shell, but shares
  the "any data here is an RCE" property.

**PHP**:
- `system`, `passthru`, `exec`, `shell_exec`, `popen`, `proc_open`
  (string form), `` ` `` backtick, `pcntl_exec` — all sh -c when given
  a string.
- `proc_open(array, ...)` — argv form (PHP 7.4+); safe.

**Go**:
- `exec.Command("sh", "-c", cmdStr)` — explicit shell.
- `exec.Command(name, args...)` — argv form, safe for class 1.
- `os/exec` is otherwise hard to misuse; Go has fewer string-form sinks.

### Source enrichment (where the data comes from)

For each sink, the bug exists when the data is attacker-controlled.
Common sources:

- HTTP request: path components, query string, headers (User-Agent,
  Referer, X-Forwarded-For, Cookie names, custom headers), body
  fields, multipart filenames.
- Environment variables: passed through the deployment harness;
  trust depends on the deployment model.
- File contents: user-uploaded files, config files in attacker-writable
  locations.
- Database rows: depends on how rows are populated; usually
  attacker-influenced.
- Inter-service calls: messages from other microservices; trust depends
  on threat model and network position.
- Filesystem listings: filenames, especially in shared upload buckets,
  email attachments, version control history.
- DNS records: TXT records, hostname components in reverse DNS — see
  Section 7 on DNS-name-as-command.

### Taint-mode patterns that catch the bug class

The canonical Semgrep taint mode shape for shell injection:

```yaml
mode: taint
pattern-sources:
  - pattern: request.$ARG
  - pattern: os.environ.get(...)
  - patterns:
    - pattern: open($PATH).read()
    - pattern-where: |
        $PATH metadata: attacker_controlled
pattern-sinks:
  - patterns:
    - pattern-either:
      - pattern: subprocess.$FN(..., shell=True, ...)
      - pattern: os.system(...)
      - pattern: os.popen(...)
pattern-sanitizers:
  - patterns:
    - pattern: shlex.quote(...)
    # WEAK — only addresses class 1; document with a comment
```

The taint-mode pattern catches class 1. For class 2, the sink must be
narrower: any sink where user input is a positional argument *and* the
target binary is known to have dangerous flags. A production static-analysis
workflow-authoring approach is to collect per-language sink+source pairs as
static evidence and pass to
a reasoning step that decides FP/TP with awareness of the target
binary's flag semantics.

### Sanitizer-aware patterns

Recognize sanitizers and weight them appropriately:

```yaml
pattern-sanitizers:
  # STRONG class-1 sanitizers
  - pattern: shlex.quote(...)          # Python
  - pattern: escapeshellarg(...)       # PHP
  - pattern: shescape.escape(...)      # Node, when interpolation=false

  # WEAK or context-dependent sanitizers; emit MEDIUM if these are
  # the only defense
  - pattern: escapeshellcmd(...)       # PHP — class 1 only, class 2 broken
  - pattern: Shellwords.escape(...)    # Ruby — class 2 broken (Stalmans)
  - pattern: shescape.escape(..., {interpolation: true})  # CVE-2022-31180
                                                          # class

  # NOT sanitizers
  - pattern: $X.replace(';', '')       # blocklist regex — not a sanitizer
  - pattern: $X.gsub(/[;|&]/, '')      # blocklist regex — not a sanitizer
```

This class of production detection workflow labels sanitizers by
strength so the rescorer correctly downgrades-but-doesn't-dismiss
weak-sanitizer findings.

### The "sanitizer is weak" rules

The `escapeshellcmd`-weak-sanitizer doctrine generalizes to a class
of rules:

- `escapeshellcmd($x)` in a CWE-78 dataflow path → MEDIUM finding with
  "escapeshellcmd is class-1 only; class 2 argv injection possible if
  target binary has dangerous flags". Do NOT dismiss as sanitized.
- `Shellwords.escape($x)` in a Ruby tar/git/curl context → MEDIUM
  finding; cite Stalmans's "the `-` is not escaped" research.
- `shescape.escape($x, {interpolation: true})` → MEDIUM; cite
  CVE-2022-31180.
- Regex-based blocklists (`$x.replace(';', '')`) → not a sanitizer;
  finding stays HIGH.
- `shlex.quote($x)` immediately followed by string concatenation
  outside a shell context → finding stays HIGH because the quote was
  pointless (no shell parser to defend against).

The pattern: sanitizer recognition is not binary. A sanitizer has a
*scope* of bug classes it addresses, and the rescorer needs to know
which class the candidate finding belongs to before crediting the
sanitizer.

### Worked example: a static-first CWE-78 detection pipeline

A production static-analysis workflow implements a static-first
detection pipeline for CWE-78 that demonstrates the sanitizer-aware
approach end-to-end:

1. **Per-sink evidence collection** (`evidence.py`): dataflow taint
   analysis, per-language sanitizer regex catalog, handler context,
   caller chains, `shell=True` literal detection.
2. **Per-language reasoning prompts** (`prompts/user_reasoning/<lang>.j2`):
   the prompt sees the sanitizer evidence and decides FP/TP.
3. **Exploitability rescorer**: a separate prompt that adjusts severity
   based on additional context. **The composer CVE-2022-24828 result**
   demonstrated the failure mode: the rescorer trusted `escapeshellcmd`
   as a strong sanitizer, downgrading a real TP. The fix (carried as
   a follow-up): label `escapeshellcmd` weak in the sanitizer catalog.

---

## 7. Defensive Patterns

### The defense ladder

Ordered from strongest to weakest:

1. **Don't run shell commands at all.** If the work can be done via
   library calls (Python `socket` module instead of `nslookup`, language
   stdlib HTTP client instead of `curl`, native git library instead of
   `git` subprocess), do that.

2. **Argv array, absolute path, allowlist binary.** When subprocess is
   unavoidable: `execve("/usr/bin/dig", ["dig", host])`. Absolute path
   defeats PATH manipulation; argv array defeats class 1; allowlist
   defeats class 2 indirectly.

3. **Argv array, absolute path, `--` arg terminator.** When the binary's
   argv parsing is the concern: `execve("/usr/bin/git", ["git", "clone",
   "--", url, dest])`. Defeats argv injection for binaries that honor `--`.

4. **`shell=True` with literal command + env-var indirection.** When
   shell features (pipelines, redirection) are unavoidable: the entire
   command is a literal; user input enters via env vars.

5. **`shell=True` with quoting library.** Acceptable only as a fallback
   when the architecture mandates it; use a battle-tested library
   (shlex.quote, escapeshellarg) and recognize the class-2 limitation.

6. **Blocklist filtering of metacharacters.** Not a defense. Treat
   findings as unsanitized.

### Container-level defenses

Defense-in-depth for hosts that must run user-supplied shell-touching
code:

- **seccomp filter on `execve`/`execveat`** — block calls entirely, or
  allowlist to a specific argv. `seccomp_load(ALLOW(execve where
  argv0 in {dig, curl}))` rejects unexpected binary calls.
- **AppArmor / SELinux profile** restricting the set of binaries the
  application may exec. The kernel enforces the allowlist even if
  application code is broken.
- **Read-only root filesystem** prevents the attacker from dropping
  payloads even if RCE is achieved.
- **No-new-privileges + non-root user** prevents privilege escalation
  from RCE.
- **`PR_SET_NO_NEW_PRIVS`** — even setuid binaries cannot regain
  privileges from a child process.

### Terminal-escape-specific defenses

- **Structured logging.** Logs are JSON; field values are encoded;
  consumers choose rendering. The architectural answer.
- **Strip `\x1b` and control characters at log-write time.** Mitigation
  level. Must be applied at every callsite, which is the weakness.
- **Strip `\x1b` at log-display time.** Use `cat -v`, `less -R` (which
  filters non-color escapes), `journalctl -o cat | cat -v`. Operator
  discipline; not architecture.
- **Use modern terminals with the dangerous features disabled.** Many
  terminals offer "secure mode" or specific feature opt-outs. iTerm2's
  "Potentially Insecure" toggle.
- **Disable title reporting.** xterm: `xterm*allowWindowOps: false`
  (keeps `GetWinTitle` in `disallowedWindowOps`).

### Code review checklist (terse, for actual use)

1. Search for `system(`, `popen(`, `exec(`, `Runtime.exec(` and verify
   each is shell-free or has a justification.
2. Search for `shell=True`, `shell: true`, backtick-strings, `%x{}` —
   each is a class-1 candidate.
3. For each subprocess sink, identify the binary being invoked. Check
   it against the dangerous-flags corpus (Section 3).
4. For each subprocess sink with user input in argv, check for `--`
   before the user position.
5. Verify sanitizers by *class*. `escapeshellcmd` is weak. `Shellwords.
   escape` is class-2 broken. `shlex.quote` is class-1 strong only.
6. For every logger call that interpolates user input, verify
   structured logging. String-format logging is a class-3 candidate.
7. Verify the deployment runs a non-root user, read-only root
   filesystem, restricted seccomp profile.
8. Verify no environment variable that the application reads is
   attacker-controllable (HTTP request headers reaching env via
   ServletRequest, Lambda runtime injecting headers, etc.).
9. For any `os.environ.get(...)`, follow the flow to subprocess sinks.
   Env vars are not sanitized.
10. For any file content read into subprocess argv, verify the file
    source is not user-influenced (uploads, git history, S3 buckets).
11. Filename-as-flag: any subprocess invocation that consumes filenames
    from a directory listing or upload bucket needs `--` or `./` prefix.
12. Where shell=True is used, verify the command string is a literal
    and user input enters via `env=` parameter.

---

## 8. Variant Analysis — Under-Explored Substrates

### Command injection in templating engines

Template engines that allow expression evaluation can reach subprocess
sinks indirectly:

**Jinja2** (Python):

```python
# Attacker controls template content (rare but happens — content
# management systems, low-code platforms)
template = Template(user_template)
template.render()
# Server-side template injection (SSTI) → eval → import os; os.system(...)
```

The SSTI-to-RCE chain is well-documented (PortSwigger's research):
once attacker controls template content, Jinja2's `{{ ''.__class__.
__mro__[1].__subclasses__() }}` chain reaches arbitrary class
instantiation and from there to `subprocess.Popen` or `os.system`.
This is *not* CWE-78 directly; it's SSTI (CWE-1336) reaching CWE-78 as
the final stage. But the detection surface for finding the pivot is
the subprocess sink catalog.

**ERB** (Ruby) — same shape. `<%= ... %>` runs Ruby; arbitrary Ruby
reaches `system` and backtick.

**Thymeleaf** (Java) — SSTI via expression preprocessing reaches
Spring SpEL, which reaches `T(java.lang.Runtime).getRuntime().exec()`.

**Velocity** (Java) — `#set` directives with `${...}` reaches
`RuntimeServices.evaluate` → class instantiation → Runtime.exec.

The Semgrep workflow at `workflows/brettonian-longsword` (CWE-1336)
handles SSTI specifically. The pivot from SSTI to shell injection is
where the two bug-class catalogs meet.

### Indirect command injection via PATH manipulation

If the application invokes a binary by relative path and the attacker
can control `$PATH`, RCE is trivial:

```python
# VULNERABLE — relative binary, attacker-controllable env
subprocess.run(["dig", host], env={"PATH": user_path})
# Attacker sets PATH=/tmp:/usr/bin and drops /tmp/dig with payload
```

Detection: any subprocess invocation with a relative binary name *and*
attacker-influenced env. Defense: absolute paths (`/usr/bin/dig`), or
set env explicitly with a known-good PATH.

### DNS-name-as-command

Some tools execute resolver output as command arguments:

- **NetworkManager dispatcher scripts** historically interpolated DHCP-
  provided option strings into shell commands. CVE-2018-1111
  demonstrated DHCP-option → command execution.
- **Mail Transfer Agents** that read MX records and pipe to commands
  may interpret special characters in MX targets.

The class generalizes: any service that reads attacker-influenced
network responses and treats them as commands is vulnerable to a
class-1 or class-2 injection driven by network response content.

### Filename-as-argv (find / xargs with adversarial filenames)

When directory contents are user-uploadable and shell commands process
filenames:

```bash
# VULNERABLE — `find` and `xargs` on a user-upload directory
find /uploads -type f | xargs cat

# Attacker uploads a file named "--help" or "--no-preserve-root".
# `xargs` reads stdin lines as argv to `cat`; the attacker-named file
# becomes a flag.
```

Defense: `find -print0 | xargs -0 cat --` — null-terminate the
filename stream and `--` terminate `cat`'s option processing. Note
that filenames containing newlines defeat the unquoted form
regardless of escaping; null-termination is the only structural fix.

### Environment-variable injection into LD_PRELOAD / LD_LIBRARY_PATH

If the application can be made to set LD_PRELOAD or LD_LIBRARY_PATH
before exec'ing another binary, the loaded library executes during
that binary's initialization:

```python
# VULNERABLE — attacker controls env passed to subprocess
subprocess.run(["sudo", "-u", "admin", "id"], env=attacker_controlled_env)
# Attacker sets LD_PRELOAD=/tmp/evil.so; sudo's init loads it
```

sudo and other setuid binaries strip `LD_PRELOAD` from their
environment in modern versions, but non-setuid binaries don't, and
"attacker-controlled env to a subprocess" is broader than just sudo.
Defense: do not pass user-influenced env to subprocess; specifically
filter LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT.

### printf format-string-to-command via `%n`-class abuse

Less common in modern code, but `printf "%s"` with a user-controlled
format-string argument that includes `%n` triggers memory writes (in
C); chained with stack manipulation it has historically reached
`execve`. The bug class still appears in legacy CGI scripts and some
embedded firmware that uses `printf` family functions on user input.

### Process-substitution injection

```bash
# VULNERABLE — diff's args come from user input
diff <(curl "$URL1") <(curl "$URL2")
# If $URL1 contains shell metacharacters, the bash process-substitution
# parsing is the substrate, not curl's URL parsing.
```

Process substitution is a bash/zsh feature; the parser runs the inner
commands during expansion. Any code that constructs `<(...)` strings
with user input is class-1 vulnerable through a non-obvious path.

### Custom shells and embedded interpreters

Devices and applications that ship their own shell-like interpreters
(industrial control systems, BMCs, IoT firmware) typically have less
hardened parsers than POSIX shells. The `firmware_embedded_security.md`
expertise doc covers the class generally; the specific lesson for
shell injection is that "this device's shell" is not bash and may
have unusual metacharacters, weaker quoting rules, or undocumented
commands.

---

## 9. Cross-Links to Sibling Expertise

- **`semgrep_rule_authoring.md`** — for the mechanics of writing
  taint-mode rules that catch the CWE-78 / CWE-88 / CWE-150 sinks
  enumerated here.
- **`code_review_expertise.md`** — Section 5 (format strings),
  Section 4 (absolute paths), Section 6 (serialization) intersect
  with shell injection through templating and deserialization-to-exec
  chains.
- **`deserialization_expertise.md`** — many deserialization gadget
  chains terminate in `Runtime.exec` / `subprocess`, so the
  shell-injection sink catalog is the convergence point of both
  bug classes.
- **`http_web_security.md`** — covers the HTTP-source side; reaches
  shell-injection findings through header injection and request-body
  parsing.
- The doctrine that `escapeshellcmd` must be labeled weak in
  CWE-78 detection workflows (§6 above) — a recurring source of
  rescorer overtrust in production static-analysis pipelines.

---

## 10. References

### Primary research

- HD Moore, "Terminal Emulator Security Issues" (2003) —
  https://hdm.io/writing/termulation.txt
- David Leadbeater, "ANSI Terminal security in 2023 and finding 10
  CVEs" (Oct 2023) — https://dgl.cx/2023/09/ansi-terminal-security
- David Leadbeater, "Déjà vu: Ghostly CVEs in my terminal title"
  (Dec 2024) — https://dgl.cx/2024/12/ghostty-terminal-title
- David Leadbeater, "Terminally Owned — 60 years of escaping"
  (DEF CON 31) — https://forum.defcon.org/node/245741
- Alessio Della Libera (Snyk), "Rediscovering argument injection when
  using VCS tools — git and mercurial" (Aug 2022) —
  https://snyk.io/blog/argument-injection-when-using-git-and-mercurial/
- Etienne Stalmans, "Argument injection and getting past
  shellwords.escape" (Nov 2019) —
  https://staaldraad.github.io/post/2019-11-24-argument-injection/
- Etienne Stalmans, "CVE-2019-13139 — Docker build code execution"
  (Jul 2019) —
  https://staaldraad.github.io/post/2019-07-16-cve-2019-13139-docker-build/
- Eviatar Gerzi (CyberArk), "Don't Trust This Title: Abusing Terminal
  Emulators with ANSI Escape Characters" (Jan 2022) —
  https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
- William Bowling (Hacker101), "The journey of finding and exploiting a
  bug in GitLab" (HacktivityCon 2020) —
  https://www.hacker101.com/conferences/hacktivitycon2020/gitlab.html
- Eric Cornelissen, shescape SECURITY.md and advisories —
  https://github.com/ericcornelissen/shescape/blob/main/SECURITY.md
- Gregory Gilliss, "Introduction to CGI and CGI vulnerabilities"
  (Phrack 49-8, Nov 1996) — https://phrack.org/issues/49/8
- Rain Forest Puppy (Jeff Forristal), "Perl CGI Problems"
  (Phrack 55-7) — https://phrack.org/issues/55/7

### Foundational documentation

- OWASP, "OS Command Injection Defense Cheat Sheet" —
  https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- PortSwigger, "What is OS command injection, and how to prevent it?" —
  https://portswigger.net/web-security/os-command-injection
- PHP, `escapeshellarg` and `escapeshellcmd` manual pages —
  https://www.php.net/manual/en/function.escapeshellarg.php and
  https://www.php.net/manual/en/function.escapeshellcmd.php
- Python, `subprocess` and `shlex.quote` documentation —
  https://docs.python.org/3/library/subprocess.html
- iTerm2 proprietary escape codes —
  https://iterm2.com/3.2/documentation-escape-codes.html
- OSC 8 hyperlinks reference (egmontkob) —
  https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda

### CVE / GHSA — Kurt Boberg

- CVE-2022-30123 — Rack Lint/CommonLogger terminal-escape injection.
  Advisory: https://github.com/advisories/GHSA-wq4h-7r42-5hrr.
  RubySec: https://rubysec.com/advisories/CVE-2022-30123/.
  Rails-discuss: https://discuss.rubyonrails.org/t/cve-2022-30123-possible-shell-escape-sequence-injection-vulnerability-in-rack/80728.
- CVE-2021-42740 — shell-quote npm regex character-class bug.
  Advisory: https://github.com/advisories/GHSA-g4rg-993r-mgx7.
  NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-42740.
  Snyk: https://security.snyk.io/vuln/SNYK-JS-SHELL-QUOTE-1766506.

### CVE / GHSA — shescape (Cornelissen)

- CVE-2022-31180 — insufficient escaping of whitespace.
  https://nvd.nist.gov/vuln/detail/CVE-2022-31180.
  Snyk: https://security.snyk.io/vuln/SNYK-JS-SHESCAPE-2952704.
- CVE-2022-31179 — code injection on Windows (cmd.exe) via line feed.
  https://security.snyk.io/vuln/SNYK-JS-SHESCAPE-2952703.
- CVE-2026-30916 — symlink chain misidentification.
  https://github.com/ericcornelissen/shescape/security/advisories/GHSA-6f6w-6j58-rq76.
- CVE-2026-32094 — bracket glob expansion bypass on Bash/BusyBox/Dash.
  https://github.com/ericcornelissen/shescape/security/advisories/GHSA-9jfh-9xrq-4vwm.
- CVE-2023-35931, CVE-2023-40185, CVE-2025-30222 — continued bypass
  series — see shescape SECURITY.md.

### CVE / GHSA — argv injection (Della Libera corpus)

- CVE-2022-25900 — git-clone npm. https://github.com/advisories/GHSA-8jmw-wjr8-2x66.
- CVE-2022-24433 — simple-git. https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-2421199.
- CVE-2022-25766 — ungit. https://security.snyk.io/vuln/SNYK-JS-UNGIT-2414099.
- CVE-2022-25648 — Ruby `git` gem. https://security.snyk.io/vuln/SNYK-RUBY-GIT-2421270.
- CVE-2022-25866 — czproject/git-php. https://security.snyk.io/vuln/SNYK-PHP-CZPROJECTGITPHP-2421349.
- CVE-2022-23915 — Weblate Python. https://security.snyk.io/vuln/SNYK-PYTHON-WEBLATE-2414088.
- CVE-2022-24828 — composer (git/hg argv injection via branch names).
  Listed across multiple sources; PHP Composer GHSA series.

### CVE / GHSA — terminal escape (Leadbeater 2023)

- CVE-2022-45872 (iTerm2 DECRQSS).
- CVE-2022-44702 (Windows Terminal/WSL working directory).
- CVE-2022-47583 (mintty DECRQSS) + CVE-2023-39726 (mintty OSC 50).
- CVE-2022-45063 (xterm OSC 50 + Zsh vi-mode).
- CVE-2022-46387 + CVE-2023-39150 (ConEmu title reporting).
- CVE-2022-4170 (rxvt-unicode Perl eval).
- CVE-2022-23465 (SwiftTerm DECRQSS).
- CVE-2022-46663 (less OSC 8 termination bypass).
- Consolidated at https://dgl.cx/2023/09/ansi-terminal-security.

### Argument-injection background

- Liran Tal (Snyk), "Command Injection vulnerability in
  git-clone-or-pull@2.0.1" —
  https://gist.github.com/lirantal/327e9dd32686991b5a1fa6341aac2e7b.
- PayloadsAllTheThings, "Command Injection" —
  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md.
- HackTricks, "Bypass Linux Restrictions" —
  https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions.
- commixproject, "Filters bypass examples" —
  https://github.com/commixproject/commix/wiki/Filters-bypass-examples.

### Historical and supplementary

- Aikido, "Command injection in 2024 report: How vulnerable we are" —
  https://www.aikido.dev/blog/command-injection-in-2024-unpacked.
- Fastly, "OS Command Injection Explained" —
  https://www.fastly.com/blog/back-to-basics-os-command-injection.
- BAE Systems Threat Research Blog, "Security issues with Using PHP's
  Escapeshellarg" (2013) —
  https://baesystemsai.blogspot.com/2013/11/security-issues-with-using-phps.html.
- "What else should you know about argument injection at
  OS commanding vulnerabilities" —
  https://d0znpp.medium.com/what-else-should-you-know-about-argument-injection-at-os-commanding-vulnerabilities-827a0b63c003.
- Cloudflare, "Inside Shellshock: How hackers are using it to exploit
  systems" — https://blog.cloudflare.com/inside-shellshock/.
- "Shell injection without whitespace" (shift or die, 2011) —
  https://shiftordie.de/blog/2011/12/23/shell-injection-without-whitespace/.

