# Bash, Zsh, and POSIX-sh Behavioral Footguns — Shell-Language Primitives That Are Unsafe by Default
## Synthesized from the Chet Ramey bash-maintenance corpus, Greg Wooledge's BashFAQ / BashPitfalls canon, the Stéphane Chazelas Shellshock analysis, the Vidar Holen ShellCheck rule catalog, and the OpenBSD / pdksh / zsh institutional voices that have catalogued shell-script footguns for thirty years

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — companion docs cover C/C++,
> C#/.NET, Go, Python, JavaScript/Node, PHP, and Ruby. Shells (bash, zsh, and
> POSIX sh) earn a dedicated doc because the surface is unusually large and
> unusually subtle: every variable expansion is a parsing event, every glob is
> a filesystem read, every command substitution is a subprocess, and the same
> three-character token (`$x`, `"$x"`, `'$x'`) produces three radically
> different evaluation trees. The 2024-2026 load-bearing updates are: macOS
> Catalina's switch from bash-3.2 to zsh-as-default (CVE-2021-45444 surface
> moved with it); and the broad adoption of "strict-mode bash"
> (`set -euo pipefail` + IFS discipline) as the default convention for new
> shell scripts in well-run codebases.
>
> **Researchers:**
> - **Chet Ramey** — Case Western Reserve
>   University; primary maintainer of GNU bash since approximately 1990
>   (sole maintainer since approximately 1993); maintainer of the GNU
>   Readline library; author of the "Bash, the Bourne-Again Shell" paper
>   and the running "Bash Reference Manual." The canonical institutional
>   voice on every bash semantic decision, every CHANGES entry, and every
>   `compat`-shopt that exists because some real script depended on the old
>   behavior
> - **Greg Wooledge ("greycat")** — long-running #bash IRC channel regular;
>   maintainer of the *BashFAQ*, *BashGuide*, *BashPitfalls*, and *WordSplitting*
>   wiki pages at `mywiki.wooledge.org`. The single most-cited corpus on
>   "thing that looks like it should work in bash but doesn't, and the precise
>   reason why." The 60+ canonical pitfalls (most reproducible in 1 line)
>   anchor §§2-7 of this document
> - **Stéphane Chazelas** — Unix and Linux network/telecom administrator; the
>   discoverer of CVE-2014-6271 ("Shellshock") who privately reported the bug
>   to Chet Ramey on 2014-09-12; the
>   canonical voice on the corner cases of POSIX sh portability and on the
>   environment-as-attack-surface failure mode that defines §13
> - **Vidar Holen** — author and maintainer of *ShellCheck*, the canonical
>   bash/sh static analyzer (written in Haskell; first released 2012; now the
>   most-starred Haskell project on GitHub). Author of the SC-numbered rule
>   catalog and the *Vidar's Blog* "Lessons learned from writing ShellCheck"
>   post. ShellCheck's rule numbers are used throughout this document as the
>   primary identifier for each footgun (cross-referenced to `shellcheck.net/wiki`)
> - **Paul Vixie** — Internet Hall of Fame inductee (2014); primary author of
>   BIND 8 at DEC and ISC; founder of the
>   Internet Software Consortium (1994) and Farsight Security (2013). The
>   institutional voice on the historical-Bourne-shell side of POSIX-sh
>   portability concerns that show up in §1 and §12
> - **Theo de Raadt** — founder and leader of the OpenBSD and OpenSSH projects
>   (OpenBSD founded October 1995); OpenBSD's
>   `ksh(1)` is based on the Public Domain Korn Shell (pdksh).
>   The institutional voice on "what the Korn-shell heritage looks like when
>   maintained by a security-conscious upstream" and on the auditing tradition
>   that informs the OpenBSD base-system shell-script style
> - **Peter Stephenson** — long-running zsh maintainer and author of *zsh: From
>   Bash to Z Shell* (with Oliver Kiddle and Jerry Peek, 2005); author of the
>   *Z-Shell Reference Manual* and *Z-Shell User's Guide* documentation set;
>   the canonical institutional voice on zsh-specific expansion rules, glob
>   qualifiers, and the `setopt` matrix discussed in §14
> - **Florian Weimer** — Red Hat Product Security; the engineer who discovered
>   CVE-2014-7186 and CVE-2014-7187 in the Shellshock patch chain and
>   contributed bash43-027; long-running participant in the bash-bug and
>   oss-security mailing-list discussions that codified the post-Shellshock
>   environment-variable hygiene rules
>
> **Institutional contributors:** the GNU Bash Reference Manual (`gnu.org`);
> the *POSIX.1-2024 Shell and Utilities* specification (Open Group / IEEE
> 1003.1-2024); Greg Wooledge's `mywiki.wooledge.org` (BashFAQ, BashGuide,
> BashPitfalls, WordSplitting, IFS, glob); the ShellCheck wiki
> (`shellcheck.net/wiki`); the *Z Shell Reference Manual*
> (`zsh.sourceforge.io/Doc/Release`); MITRE CVE entries for CVE-2014-6271
> ("Shellshock"), CVE-2014-7169, CVE-2014-6277, CVE-2014-6278, CVE-2014-7186,
> CVE-2014-7187, and CVE-2021-45444 (zsh prompt-expansion); CISA Alert
> TA14-268A ("GNU Bourne-Again Shell (Bash) 'Shellshock' Vulnerability");
> the OpenWall `oss-security` mailing list archive (the load-bearing public
> record of the Shellshock disclosure timeline); the OpenBSD `ksh(1)` man
> page (the canonical concise reference for Korn-derived shell semantics);
> the *Advanced Bash-Scripting Guide* (Mendel Cooper, TLDP) for historical
> reference (with the caveat that some of its examples have aged past
> current shell-style consensus).
>
> **What this doc is NOT:** not a bash tutorial; not a shell-injection bug
> class explainer (see the cross-link below — that doc covers the **cross-
> language** "pass user input to a shell" bug; this doc covers the **shell-
> language-internal** quirks that bite shell-script authors); not a guide to
> writing shell-portable code across every historical sh variant (see the
> POSIX.1-2024 spec); not an exploitation manual for Shellshock and its
> kin (see §13 for the audit-focused summary). It is the language-specific
> layer beneath cross-language audit heuristics: what shell primitives are
> *unsafe by default*, what the auditor should treat as a candidate point,
> and what the script author should treat as an alarm bell.

Cross-links: see `shell_injection_expertise.md` for the **cross-language bug
class** (passing user-controlled strings to a shell from a higher-level
language like Python's `subprocess(shell=True)`, Ruby's backticks, or
Node's `child_process.exec`); the present document is the **shell-language-
internal complement** — it covers footguns that bite you while you are
already inside a `.sh`/`.bash`/`.zsh` script. See `code_review_expertise.md`
for the click-count severity heuristic and the candidate-point auditing
pattern (§16 here is the shell-script-specific elaboration of §2 there).
See the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for detection-rule authoring guidance and
the `language: bash` / `generic` / `regex` mode tradeoffs (referenced
explicitly in §15). See `cicd_supply_chain_expertise.md` for the CI/CD
pipeline context where shell scripts cross trust boundaries (most modern
Shellshock-equivalent exposure today is through GitHub Actions `run:` blocks
and similar CI step bodies — see §13).

---

## 1. The behavioral-footgun framing

This document covers **shell-language-internal footguns** — primitives in
bash, zsh, and POSIX sh that produce surprising or unsafe behavior under
their *default* settings, regardless of whether the script ever touches
user input. It is deliberately distinct from the cross-language "shell
injection" bug class.

### 1.1 What this is, and what it isn't

The cross-language bug — *shell injection* — is "a higher-level language
passes an attacker-controlled string to a shell, and the shell parses
it as code." Covered in `shell_injection_expertise.md`. The fix is
structural: pass argv arrays to `execve(2)` directly.

The shell-language-internal class — this document — is "you are writing
a `.sh`/`.bash`/`.zsh` file, the shell semantics you assumed are wrong,
and your script breaks (deletes the wrong file, leaks a secret to a log,
runs the wrong code path) even when no attacker is involved." The fix is
*idiomatic*: learn the rule, encode it in a linter (ShellCheck), refactor.

The two overlap when (1) a shell script is the *target* of a higher-level
injection (Shellshock); (2) a shell script handles partly-trusted input
internally (a CI bootstrap that `eval`s `$GITHUB_REF`); (3) the script
makes outbound calls with unquoted variables (`curl $URL`), which is
simultaneously shell-internal and cross-language. Both expertises apply.

Heuristic: if the failure mode requires an attacker, consult the parent
doc. If the failure happens with the script's own expected inputs (a
filename with a space; a missing variable; a zero-match glob), this doc
applies.

### 1.2 The three shells

- **POSIX sh** — the standardized minimum (POSIX.1-2024). On Linux,
  `/bin/sh` is typically `dash`, `bash`-in-POSIX-mode, or `busybox`.
  Bootstrap scripts (Debian preinst, BSD `/etc/rc.subr`) must be
  POSIX-portable.
- **bash** — the GNU Bourne-Again Shell. Maintained by Chet Ramey at
  Case Western Reserve since approximately 1990 (sole maintainer since
  approximately 1993). Default `/bin/bash` on most distributions.
- **zsh** — the Z Shell. Default interactive shell on macOS since
  Catalina (2019). Maintained by Peter Stephenson.

The three families have **different semantics for the same syntax**.
Canonical example: bash performs word-splitting on unquoted parameter
expansion by default; zsh does **not** (unless `setopt SH_WORD_SPLIT`).

The shebang picks the interpreter. `#!/bin/sh` is POSIX-only. `#!/usr/bin/env
bash` enables bash features. The footgun is *no shebang at all*: the
script is interpreted by whatever shell the parent used — `zsh` on a
developer laptop, `bash`/`dash` in production. Always declare a shebang.

### 1.3 Framing rule for the rest of this document

For each section: state the default, state the surprising-but-correct
behavior, state the safer idiom, cite the ShellCheck rule that codifies
it. Where CVE history exists — §13, §14 — it is called out explicitly.

---

## 2. Word-splitting and IFS

Word-splitting is the single largest source of shell-script bugs that
look like "this should obviously work" and don't. The mechanism is
inherited from the original Bourne shell, codified by POSIX, and is the
load-bearing primitive behind ~half of the BashPitfalls entries.

### 2.1 The IFS default

The Internal Field Separator (`IFS`) is a shell variable. Its default
value is the three-character string `<space><tab><newline>`. After any
parameter expansion, command substitution, or arithmetic expansion that
is *not* inside double quotes, the shell splits the result into "words"
by treating any run of IFS characters as a delimiter.

```bash
list="alpha  beta	gamma"     # two spaces, one tab
for w in $list; do echo "$w"; done
# Output (default IFS):
# alpha
# beta
# gamma
```

The split happens on the *result of expansion*. The expansion-then-split
sequence is the key insight: the shell first replaces `$list` with the
literal string `alpha  beta\tgamma`, *then* splits that string on IFS,
*then* hands each resulting word to `for` as a separate iteration. The
spaces in the original string are gone; only the word boundaries remain.

### 2.2 The "I wanted one argument but got three" failure

```bash
filename="my report.txt"
ls -l $filename
# Equivalent to:
ls -l my report.txt
# ls sees TWO arguments: "my" and "report.txt"
```

The script author intended `ls -l 'my report.txt'`. The shell saw
`ls -l my report.txt` after expansion and word-splitting. `ls` then
prints "cannot access 'my'" and "cannot access 'report.txt'" — both
failures.

The fix is **double-quote every variable expansion**:

```bash
filename="my report.txt"
ls -l "$filename"            # one argument, with the space preserved
```

ShellCheck rule **SC2086** — "Double quote to prevent globbing and word
splitting" — flags every unquoted variable expansion. It is the single
most-frequently-cited ShellCheck rule. The number of bash scripts in the
wild that survive only because no filename has yet contained a space is
itself a load-bearing observation.

### 2.3 The `for f in $(ls)` antipattern

```bash
for f in $(ls); do echo "$f"; done   # BROKEN
```

This pattern appears in tens of thousands of tutorials and is wrong in
two compounding ways. First, the output of `ls` is split on IFS, which
means filenames with spaces, tabs, or newlines are torn apart into
separate iterations. Second, the output of `ls` is then subjected to
**pathname expansion** (globbing), which means a filename that happens
to contain `*`, `?`, or `[...]` will be re-expanded against the current
working directory's contents. The combined effect is "this works on a
clean tutorial corpus and fails as soon as a real filesystem is
involved."

The two correct idioms:

```bash
# Idiom 1: glob directly. Bash performs pathname expansion safely as a
# single unit, with each result preserved as a separate argument.
for f in ./*; do echo "$f"; done

# Idiom 2: null-delimited find + read. Robust against any filename.
find . -maxdepth 1 -print0 | while IFS= read -r -d '' f; do
    echo "$f"
done
```

The `./` prefix in `for f in ./*` is also load-bearing — it ensures the
expanded filenames cannot begin with a `-`, which would otherwise look
like a command-line option to downstream commands (see §3.1).

### 2.4 The `read` + IFS interaction

The `read` builtin respects `IFS` for line-internal splitting. Without
the `-r` flag, it also interprets backslashes as line-continuation. The
canonical "preserve every byte of a line as-is" idiom is:

```bash
while IFS= read -r line; do
    process "$line"
done < file.txt
```

Three things at once: `IFS=` for *this command only* (so leading and
trailing whitespace are preserved), `-r` (so backslashes are not
interpreted), and the redirection inside a `while` loop instead of the
`cat file | while ...` pipe (which would run the loop in a subshell —
see §9.2). ShellCheck has a rule for each: SC2162 for missing `-r`,
SC2030/SC2031 for the subshell-variable trap.

### 2.5 Newline-only IFS

For "split on newline only, not on spaces or tabs," the canonical idiom
is:

```bash
IFS=$'\n'
for line in $(grep ERROR /var/log/syslog); do
    handle "$line"
done
IFS=$' \t\n'                # restore default
```

Or, scoped locally:

```bash
while IFS= read -r line; do ...; done < <(grep ERROR /var/log/syslog)
```

The second form is preferred. The first form mutates a global and
relies on the restore; if the body of the loop has an early `return` or
`exit`, the IFS change leaks.

### 2.6 The `read -d ''` + `find -print0` pattern

For arbitrary filenames — including those with spaces, newlines, glob
chars, leading hyphens, UTF-8:

```bash
find . -type f -print0 | while IFS= read -r -d '' f; do
    process "$f"
done
```

`find -print0` separates with NUL (the one byte forbidden in filenames);
`read -r -d ''` reads up to NUL. The only fully-correct idiom for
"iterate over filenames" in shell. Bash-4.4+ alternative is `mapfile -d ''`,
which is faster but absent on macOS-default bash 3.2 (§8.4).

### 2.7 Quoting prevents both splitting and globbing

- `$var` — splits on IFS, then globs each resulting word.
- `"$var"` — does neither. One literal string.
- `'$var'` — no expansion; four literal characters.

ShellCheck SC2086 catches the unquoted case. Bias is to always quote.

---

## 3. Glob expansion and pathname expansion

The shell performs **pathname expansion** (globbing) on every unquoted
word that contains `*`, `?`, `[`, or `{` (with brace expansion as a
prior step). The result is a list of matching filenames, sorted
lexically by default.

### 3.1 `rm *.txt` and the leading-hyphen problem

```bash
$ touch -- '-rf' '/'   # don't do this on a real system
$ rm *
# * may expand to "-rf file.txt" — rm parses -rf as flags
```

If the current directory contains a file named `-rf`, then `rm *`
becomes `rm -rf <other files>` — `rm` parses `-rf` as flags. This is
the canonical "filename-as-option-injection" attack against shell
scripts.

The fix is `--` end-of-options:

```bash
rm -- *.txt
```

`--` is parsed by getopt-style argument parsers (including GNU coreutils)
as "everything after this point is a positional argument, not an
option." It is a one-character defense that should appear in essentially
every shell script that expands a glob into a command's arguments.

ShellCheck SC2035 flags glob-as-first-argument patterns and suggests
`./` or `--` prefixes.

### 3.2 Hidden files (`.foo`) and `dotglob`

By default, globs do **not** match files whose names start with a dot:

```bash
$ ls -A
.hidden visible.txt
$ for f in *; do echo "$f"; done
visible.txt                          # .hidden was skipped
```

To include dotfiles in `*` expansion, bash has `shopt -s dotglob`. Zsh
has `setopt GLOB_DOTS`. Both are off by default.

The footgun is the other direction: a backup-script author writes
`tar czf backup.tar.gz *` to back up "everything in the current
directory" and silently omits all dotfiles. The fix is either to enable
`dotglob` or to use an explicit pattern (`tar czf backup.tar.gz . `
with `.` as the directory argument, which `tar` handles correctly).

### 3.3 `nullglob`, `failglob`, and the literal-pattern trap

The default bash behavior when a glob matches nothing is to leave the
glob *literal*:

```bash
$ ls /nonexistent/*.txt
ls: cannot access '/nonexistent/*.txt': No such file or directory
$ for f in /nonexistent/*.txt; do echo "got: $f"; done
got: /nonexistent/*.txt              # literal pattern, one iteration
```

This bites every shell-script author who writes a "for each matching
file" loop and assumes the loop runs zero times when there are zero
matches. The loop runs **once**, with the unmatched pattern as the
value of `$f`.

Three fixes:

```bash
# Option A: shopt -s nullglob — empty glob expands to nothing
shopt -s nullglob
for f in /tmp/*.log; do
    # If there are no matches, the loop body does not execute at all.
    process "$f"
done

# Option B: shopt -s failglob — error on no-match
shopt -s failglob
for f in /tmp/*.log; do  # script aborts here if no matches
    process "$f"
done

# Option C: explicit existence check
files=( /tmp/*.log )
if [[ -e "${files[0]}" ]]; then
    for f in "${files[@]}"; do process "$f"; done
fi
```

`nullglob` is the bias for "iterate over zero-or-more matches"
patterns. `failglob` is the bias for "fail fast if I expected a match"
patterns. The default — literal-pattern fallback — is what bites
script authors. ShellCheck SC2144 covers a related pattern (`[ -e
*.txt ]` with `-e` taking only one argument).

Zsh's defaults differ: zsh's default `NOMATCH` option makes an
unmatched glob an error (*failglob*-like), and its `setopt NULL_GLOB` mirrors bash's
`nullglob`. Scripts ported between the two should declare their glob
behavior explicitly rather than rely on default mode.

### 3.4 Brace expansion `{a,b,c}` is not pathname expansion

```bash
$ echo {a,b,c}.txt
a.txt b.txt c.txt                    # three literal strings, regardless of FS
```

Brace expansion runs *before* pathname expansion and is purely textual.
It is **not** filtered by what is on disk. This is the source of one of
the most common porting bugs from bash to dash/POSIX-sh: brace
expansion is a bash extension and does not exist in POSIX. A script
that does `cp file.{txt,bak}` under dash will literally try to copy a
file named `file.{txt,bak}`.

ShellCheck SC3009 flags brace expansion in sh-mode scripts.

### 3.5 Range globs `[a-z]` and locale

Character-class globs are **locale-sensitive**. Unless
`globasciiranges` is on (the default since bash 5.0), `[a-z]` follows
locale collation order and can match uppercase letters such as `A`. Fix: `LC_COLLATE=C` for any script that uses range globs. Real
bug in CI/CD pipelines with non-default locales. No ShellCheck rule;
manual review only.

---

## 4. Quoting rules (single, double, backslash, `$''`)

The shell has four quoting mechanisms, each with different expansion
semantics. The interaction of quoting with the rest of the expansion
machinery is the load-bearing primitive behind §2 and §3.

### 4.1 The four modes

- **Single quotes** `'...'` — no expansion at all. Every byte between
  the single quotes is literal. There is **no way** to embed a single
  quote inside single quotes; the standard workaround is `'don'\''t'`
  (close, escape-single-quote, reopen).
- **Double quotes** `"..."` — variable expansion (`$var`),
  command substitution (`$(cmd)` / `` `cmd` ``), and arithmetic expansion
  (`$((expr))`) occur. The four characters that retain meaning inside
  double quotes are `$`, `` ` ``, `\`, and `"`. Pathname expansion
  (globbing) does **not** occur. Word-splitting on the *result* of
  expansion does **not** occur for parameter expansion of scalar
  variables (it does for `"$@"` — see §4.3).
- **Backslash** `\x` — the next character is taken literally.
  `\$` is a literal dollar sign, `\\` is a literal backslash, etc.
  Inside single quotes, backslash is itself literal.
- **ANSI-C quoting** `$'...'` — supported by bash and zsh, and
  standardized in POSIX.1-2024. Backslash escapes are interpreted: `$'\n'` is a newline,
  `$'\t'` is a tab, `$'\x41'` is `A`, `$'é'` is `é`. No variable
  expansion. The canonical use is for IFS:
  `IFS=$'\n\t'`.

### 4.2 The "I quoted but forgot one place" bug

The single most common manifestation of SC2086 is a script that quotes
*most* of its variables but forgets one. Example:

```bash
path="$1"
mkdir "$path"                  # quoted, correct
cd $path                       # UNQUOTED — bug
mv "$2" "$path/destination"    # quoted, correct
```

The unquoted `cd $path` will break if `$path` contains a space, a glob
char, or is empty. The empty-variable case is particularly insidious:
`cd` with no arguments goes to `$HOME` (§12.6), so a script that
*thought* it was changing into a build directory will silently cd to
the user's home and then operate there.

ShellCheck's coverage of this pattern is comprehensive: SC2086 for the
unquoted variable, SC2164 for `cd` without `|| return` / `|| exit`,
and SC2103 for missing pushd/popd discipline.

### 4.3 `"$@"` vs `"$*"`

Inside double quotes, `$@` and `$*` have load-bearing different
semantics:

- `"$@"` expands to N separately-quoted arguments. If the script was
  called with `script "a b" "c d"`, then `"$@"` is `"a b" "c d"` —
  two arguments, with spaces preserved.
- `"$*"` expands to a *single* argument: all positional parameters
  concatenated with the first character of IFS. With default IFS,
  `"$*"` is `"a b c d"` — one argument, with the structure lost.

The canonical idiom is:

```bash
# Pass all our arguments to a subcommand, preserving structure.
exec mycommand "$@"
```

`exec mycommand "$*"` is almost always wrong — it collapses the argv
into a single string and re-introduces the same word-splitting bugs
the user thought they were avoiding by quoting in the first place.

The same `@` vs `*` distinction applies to arrays: `"${arr[@]}"` (N
separate quoted elements) vs `"${arr[*]}"` (one string).

### 4.4 Backtick vs `$()` quoting

Both perform command substitution. `$()` is POSIX (1992), nests cleanly
without escape gymnastics, and is universally preferred:

```bash
echo "$(grep $(whoami) /etc/passwd)"     # clean
echo "`grep \`whoami\` /etc/passwd`"     # escape gymnastics
```

ShellCheck SC2006 flags backticks and recommends `$()`.

### 4.5 The "did the command substitution succeed?" trap

`$()` ignores exit status. `output="$(grep "$pattern" file.txt)"` does
not distinguish "grep found nothing" from "file.txt missing." Both
produce empty `output`. Under `set -e`, a plain assignment exits on a
failed substitution, but `local`/`declare`/`export` mask it (§5.4). Fix:
check `$?` explicitly or restructure as a pipe.

---

## 5. Command substitution `$()` vs subshells `(...)` vs process substitution `<(cmd)`

These three constructs use similar syntax and have very different
semantics. Confusing them is a recurring source of bugs.

### 5.1 Command substitution `$(cmd)`

`$(cmd)` runs `cmd` in a subshell, captures its stdout, strips
trailing newlines, and substitutes the result into the surrounding
command line.

```bash
now="$(date +%s)"               # now contains the integer Unix timestamp
```

The trailing-newline stripping is a frequent surprise:

```bash
output="$(cat file_with_trailing_newlines.txt)"
# ALL trailing newlines are stripped, not just one.
```

If you need to preserve trailing newlines, append a sentinel and strip
it manually: `output="$(cat file.txt; echo X)"; output="${output%X}"`.

### 5.2 Subshell `(cmd)`

`(cmd)` runs in a subshell; no output capture. Used to scope side
effects (cwd, variables, traps):

```bash
(cd /tmp && rm -rf build)        # cwd change doesn't leak
```

Footgun: `result=(ls /tmp)` is array assignment (two elements `ls` and
`/tmp`), not command substitution. Rarely intended.

### 5.3 Process substitution `<(cmd)` and `>(cmd)`

Not POSIX; bash, zsh, and AT&T ksh support it. `<(cmd)` provides a filename (`/dev/fd/63`) that yields
`cmd`'s stdout. Canonical use: `diff <(cmd1) <(cmd2)`. Common bug:
inner-command failure is hidden — `diff` sees an empty file when
`ssh host1` fails and reports a diff instead of an error.

Process substitution also fixes the subshell trap (§9.2):

```bash
# Works: while runs in current shell.
while IFS= read -r line; do
    count=$((count + 1))
done < <(grep ERROR /var/log/syslog)
echo "$count"                    # correct

# Breaks: while runs in a subshell because of the pipe.
grep ERROR /var/log/syslog | while ...; done
echo "$count"                    # always 0
```

### 5.4 Command-substitution-failure-hidden-by-`set -e`

A plain assignment takes the exit status of its last command
substitution, so it triggers `set -e`; `local`, `declare`, and `export`
replace that status with their own:

```bash
set -e
result=$(false)                  # exits: assignment keeps the failure status
result=$(false) || exit 1        # explicit path; correct
```

ShellCheck SC2155 catches `local var=$(cmd)`, where `local`'s exit
code overrides the substitution's.

---

## 6. `set -e`, `set -u`, `set -o pipefail`, and the "strict mode" myth

The "strict mode" prelude `set -euo pipefail` is the canonical bash
hardening incantation. It is widely repeated, frequently misunderstood,
and not a security feature.

### 6.1 `set -e` — exit on error (with many exceptions)

`set -e` exits when a command exits non-zero, **except**:

1. Commands in `if`, `elif`, `while`, `until` conditions.
2. Commands in `&&` or `||` chains, except the last.
3. Commands inverted by `!`.
4. Functions called in any of the above.
5. Pipelines (only the last command's exit status counts; see §6.3).
6. Command substitutions in `local`/`declare`/`export` assignments (§5.4).

`set -e` is **not** a substitute for explicit error handling. Classic
trap:

```bash
set -e
foo() {
    false
    echo "still here"            # PRINTS — exception applies
}
foo || echo "foo failed"          # `||` context inherits the exception
```

Fix with explicit `if ! cmd; then ...; fi` or `trap '...' ERR` (which
has its own exceptions).

### 6.2 `set -u` — error on undefined variable

`set -u` causes references to undefined variables to be treated as
errors:

```bash
set -u
echo "$undefined"                # exits with an error
```

The canonical idioms for "default value" become required:

```bash
echo "${var:-default}"           # use default if var is unset OR empty
echo "${var-default}"            # use default only if var is unset (allow empty)
echo "${var:?error message}"     # exit with error message if var is unset/empty
```

`${arr[@]}` and `${arr[*]}` under `set -u` require bash 4.4+ for the
empty-array case to not error. Older bash versions exit on empty array.

### 6.3 `set -o pipefail` — pipelines fail if any stage failed

Without `pipefail`, a pipeline's exit code is the exit code of the
*last* command:

```bash
false | true                     # exits 0; the failure of false is lost
```

With `pipefail`, the pipeline's exit code is the rightmost non-zero
exit code, or zero if all succeeded:

```bash
set -o pipefail
false | true                     # exits 1; the false is now visible
```

The canonical case where pipefail bites: `set -e -o pipefail` and a
pipeline like `cat huge.gz | gunzip | head -10`. `head` exits early
once it has 10 lines, sending `SIGPIPE` to `gunzip`, which exits
non-zero. With `pipefail`, the pipeline as a whole exits non-zero, and
`set -e` then aborts the script. The fix is `head -10 || true` or
`set +o pipefail` for the specific block.

### 6.4 `set -x` — print commands as executed (leaks secrets)

`set -x` prints each command, with expansions resolved, to stderr.
Recurring CI/CD incident pattern: API token or secret echoed into a
build log that is then archived. ShellCheck does not flag `set -x`;
manual review of every CI step touching secrets is the only defense.
Wrap secret-handling code in `set +x ... set -x`, or pass secrets via
env/stdin and ensure consumers don't echo.

### 6.5 The canonical strict-mode prelude

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
trap 'echo "Error at line $LINENO" >&2' ERR
```

Convention for new bash scripts. Caveats: `set -e` is not a security
feature; explicit error handling still belongs in every load-bearing
branch; the `ERR` trap does not fire on `set -e` exceptions (§6.1).

---

## 7. `read` and input handling

`read` is the bash builtin for reading a line from stdin or a file
descriptor. Its defaults are surprising in load-bearing ways.

### 7.1 `read` without `-r` interprets backslashes

```bash
echo 'C:\Users\Alice' | { read line; echo "$line"; }
# Prints: C:UsersAlice                  — backslashes consumed
echo 'C:\Users\Alice' | { read -r line; echo "$line"; }
# Prints: C:\Users\Alice                — correct
```

`read` without `-r` interprets backslashes as line-continuation and
escape characters. Almost always wrong. The canonical idiom always
uses `-r`. ShellCheck SC2162 flags `read` without `-r`.

### 7.2 `IFS= read -r line` for whitespace preservation

```bash
echo '   leading and trailing   ' | { read -r line; echo "[$line]"; }
# Prints: [leading and trailing]        — whitespace stripped
echo '   leading and trailing   ' | { IFS= read -r line; echo "[$line]"; }
# Prints: [   leading and trailing   ]  — preserved
```

The `IFS=` is local to the `read` command (it is set as a single-command
assignment, not a global). Combined with `-r`, this is the canonical
"read a line exactly as it appears in the file" idiom.

### 7.3 `read` exit status on EOF

`read` returns non-zero on EOF *without* a trailing newline. For files
without a trailing newline (common with hand edits), the last line is
silently dropped. Fix:

```bash
while IFS= read -r line || [[ -n "$line" ]]; do
    process "$line"
done < file.txt
```

ShellCheck SC2095 covers a different read-loop bug (ssh stealing
loop stdin).

### 7.4 `mapfile` / `readarray` (bash 4+)

```bash
mapfile -t lines < file.txt
for line in "${lines[@]}"; do process "$line"; done
```

`-t` strips trailing newlines. Bash 4+, absent on macOS bash 3.2.

### 7.5 The "read user input then use it unquoted" pattern

```bash
read -p "Enter filename: " name
rm $name              # UNQUOTED — splits, globs, parses -rf
```

Fix: quote (`rm -- "$name"`) and validate (reject `^-`, reject `/` if
unexpected). Crosses into shell-injection territory — see
`shell_injection_expertise.md`.

---

## 8. Arrays and associative arrays

Arrays in bash and zsh are similar but not identical, and the two
shells disagree on indexing conventions. This is a porting trap.

### 8.1 Bash indexed arrays

```bash
arr=(alpha beta gamma)           # length 3
echo "${arr[0]}"                 # alpha
echo "${arr[@]}"                 # alpha beta gamma
echo "${#arr[@]}"                # 3 (length)
echo "${!arr[@]}"                # 0 1 2 (indices)
```

`${arr[@]}` vs `${arr[*]}` follows the same rule as `$@` vs `$*`:
inside double quotes, `"${arr[@]}"` is N separately-quoted elements,
while `"${arr[*]}"` is one string with elements joined by the first
character of IFS.

The canonical argv-construction idiom:

```bash
args=( --verbose --output "$path/with space" )
mycommand "${args[@]}"
```

This passes each array element as a separate argument with whitespace
preserved. It is the structurally correct alternative to
`eval mycommand "$args"` (which is a shell-injection footgun — see §11).

### 8.2 `unset arr[0]` does not shift

```bash
arr=(a b c)
unset 'arr[0]'
echo "${arr[@]}"                 # b c
echo "${arr[0]}"                 # (empty) — index 0 is gone
echo "${arr[1]}"                 # b
echo "${!arr[@]}"                # 1 2
```

`unset` removes the element but does not renumber. The array now has
gaps. Iteration with `${arr[@]}` works correctly (it skips holes), but
indexed access with `${arr[0]}` returns empty. ShellCheck SC2184 covers
a related issue (`unset arr[0]` without quoting can hit glob expansion
if `arr[0]` matches a file).

### 8.3 Bash associative arrays (bash 4+)

```bash
declare -A map
map[alice]=ENG
map[bob]=SALES
for key in "${!map[@]}"; do
    echo "$key => ${map[$key]}"
done
```

`declare -A` is bash 4+. The classic gotcha: macOS ships bash 3.2
(licensed under GPLv2; bash 4+ is GPLv3 and Apple does not ship GPLv3
software in the base system). A script that uses `declare -A` will
fail with "declare: -A: invalid option" on a default macOS shell. The
fix is either to install `bash` from Homebrew and set
`#!/usr/bin/env bash`, or to fall back to parallel indexed arrays.

### 8.4 The macOS bash-3.2 problem

Bash 4+ features absent on macOS-default bash 3.2: `declare -A`,
`mapfile`/`readarray`, `coproc`, `${var^^}`/`${var,,}`, `[[ -v var ]]`,
refined ERR/DEBUG trap inheritance. Scripts targeting both Linux and
macOS either install Homebrew bash and use `#!/usr/bin/env bash`, or
go POSIX-only (`#!/bin/sh`) and avoid bash-isms entirely.

### 8.5 Zsh array indexing is 1-based

```zsh
arr=(alpha beta gamma)
echo $arr[1]                     # alpha
```

`setopt KSH_ARRAYS` enables 0-indexed bash-compatible behavior. Canonical
bug: a bash script with `${arr[0]}` sourced under zsh silently reads
empty.

### 8.6 Zsh `setopt SH_WORD_SPLIT`

Zsh does *not* word-split unquoted parameter expansion by default.
`list="a b c"; for w in $list` prints 3 lines under bash, 1 under zsh.
`setopt SH_WORD_SPLIT` restores bash compatibility. Better: declare
an array up-front and iterate it explicitly — works under both shells.

---

## 9. Functions, subshells, and `source`

The shell has three execution scopes that are visually similar and
operationally very different.

### 9.1 Function vs subshell

```bash
f() { x=in_function; }
f
echo "$x"                        # in_function — variable in parent

g() ( x=in_subshell; )
g
echo "$x"                        # in_function — g's assignment didn't leak
```

A function with `{ ... }` runs in the current shell. A function with
`( ... )` runs in a subshell — every assignment, `cd`, `umask`,
`trap`, `set` change is local. This is occasionally useful for "I want
to keep the side effects contained" patterns but the visual similarity
to regular functions is a recurring source of confusion.

### 9.2 The pipe-to-while subshell trap

```bash
count=0
seq 1 100 | while read line; do
    count=$((count + 1))
done
echo "$count"                    # 0 — count was modified in the subshell
```

Any command on the right side of a pipe runs in a subshell (in bash;
ksh93 differs; zsh runs the last element in the current shell). The `while`
loop's `count` modification happens in that subshell, and the parent
shell never sees it.

Three fixes:

```bash
# Fix A: process substitution
count=0
while read line; do
    count=$((count + 1))
done < <(seq 1 100)
echo "$count"                    # 100

# Fix B: redirect from file directly (when source is a file, not a pipeline)
count=0
while read line; do
    count=$((count + 1))
done < /tmp/lines
echo "$count"

# Fix C: bash-specific, shopt -s lastpipe
shopt -s lastpipe
seq 1 100 | while read line; do
    count=$((count + 1))
done
echo "$count"                    # 100 — but only if shopt is set
```

ShellCheck SC2030/SC2031 flag variables modified inside a pipe-fed
loop.

### 9.3 `source` vs invoking a script

```bash
source script.sh                 # runs in current shell; variables leak
. script.sh                      # synonym for source (POSIX)
bash script.sh                   # runs in a new process; variables don't leak
./script.sh                      # runs in a new process (uses the shebang)
```

Inside a sourced script, `exit` terminates the **parent** shell —
which means a sourced helper that has `exit 1` will close the user's
terminal. The canonical workaround is `return 1` inside a function, or
checking `${BASH_SOURCE[0]}` against `$0`:

```bash
# In script.sh:
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # being executed directly
    exit 1
else
    # being sourced
    return 1
fi
```

### 9.4 `return` outside a function

`return` is only valid inside a function or a sourced script. Using
`return` at the top level of a non-sourced script is a runtime error
("can only `return' from a function or sourced script"), not a syntax
error; outside POSIX mode bash keeps running the script.
ShellCheck SC2104 covers a related pattern (`break` in a function, where `return` was meant).

---

## 10. Signal handling and traps

`trap` installs handlers for signals and a small set of bash-synthesized
pseudo-signals (`EXIT`, `ERR`, `DEBUG`, `RETURN`).

### 10.1 `trap 'cleanup' EXIT`

```bash
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
# ... use $tmpdir ...
```

The `EXIT` pseudo-signal fires on any script exit — normal completion,
`exit N`, signal-caused termination after handler returns, `set -e`
abort. It is the canonical "always cleanup" hook.

Idioms and gotchas:

- The trap action is a *string*, not a command. Variables are expanded
  at *trap time*, not at *fire time*. Use single quotes to defer
  expansion: `trap 'rm -rf "$tmpdir"' EXIT` (correct, `$tmpdir`
  expanded at exit) vs `trap "rm -rf $tmpdir" EXIT` (wrong if `$tmpdir`
  is set after the trap line).
- Setting a new trap for the same signal *replaces* the old one. To
  chain, capture the existing trap with `trap -p EXIT` and concatenate.
- `trap '' SIGNAL` ignores the signal. `trap - SIGNAL` resets to
  default.
- Traps are not inherited by subshells unless `set -E` (functions) /
  `set -T` (DEBUG/RETURN) are set.

### 10.2 The `mktemp -d` + trap-cleanup canonical idiom

```bash
#!/usr/bin/env bash
set -euo pipefail
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
```

Canonical safe scaffolding for filesystem-touching scripts. Two common
bugs: (1) trap installed after a command that may fail leaks the temp;
order is create, trap, use. (2) `mktemp -d` failed and `tmpdir` is
empty. Defense:
`rm -rf "${tmpdir:-/nonexistent}"`.

### 10.3 `trap '...' ERR`

`ERR` fires on non-zero exit under the same rules as `set -e` (all
§6.1 exceptions apply). Useful for diagnostic logging:
`trap 'echo "Error at $LINENO" >&2' ERR`. Bash-synthesized; absent in
POSIX sh.

### 10.4 Signal masks across `exec` and subshells

`exec` replaces the shell process. Traps are **not** inherited; the
new program runs with its own signal-handler defaults. An `EXIT` trap
followed by `exec` never fires. Fix: if cleanup is needed, don't `exec`
— run the child and let the trap fire at script end.

---

## 11. `eval` and dynamic execution

`eval` is the most direct way to introduce shell injection inside a
shell script. It exists for legitimate purposes — primarily for setting
variables whose names are computed at runtime — but is almost always
the wrong answer in modern bash.

### 11.1 `eval "$string"`

`eval` takes its arguments, concatenates them, and feeds the result to
the shell parser as a new command line. Every expansion that has
already happened is re-run by `eval`:

```bash
cmd='echo $HOME'
eval "$cmd"                       # prints the value of HOME
```

If any portion of `cmd` is attacker-controlled, this is a shell-
injection bug. The footgun is that this looks identical to legitimate
indirection patterns. ShellCheck SC2294 flags `eval` applied to an
array or `"$@"`.

The cross-link: see `shell_injection_expertise.md` for the bug class
treatment. The present document covers the shell-internal failure mode
(unexpected double expansion of bash metacharacters in variables that
the author thought were "just data").

### 11.2 Indirect variable reference `${!name}`

The bash-specific `${!var}` syntax dereferences `$var` as the *name* of
another variable:

```bash
target=HOME
echo "${!target}"                # prints the value of HOME
```

This is the safe alternative to `eval "echo \$$target"` for most
indirection cases. ShellCheck does not have a specific rule for
`${!var}` (it is generally fine).

### 11.3 `declare -n` namerefs (bash 4.3+)

```bash
declare -n ref=actual_variable
ref="hello"
echo "$actual_variable"          # hello
```

`declare -n` (or `local -n` inside a function) creates a name reference
— `ref` is now an alias for `actual_variable`. This is the modern
indirection idiom and replaces both `eval` and `${!var}` for most
patterns. Caveat: bash 4.3+, so not available on macOS-default 3.2.

### 11.4 `printf -v variable_name format args`

For "print the formatted result into a variable":

```bash
printf -v greeting "Hello, %s!" "$user"
echo "$greeting"
```

`printf -v` is the canonical bash idiom for capturing formatted output
without spawning a subshell. The pitfall: if `variable_name` itself is
attacker-controlled, this is a variable-name-injection footgun
analogous to `declare`-based injection. ShellCheck does not have a
specific rule, but as a heuristic: never let `variable_name` be
user-derived.

### 11.5 `command -v` vs `which`

For "does this command exist?":

```bash
if command -v curl >/dev/null 2>&1; then
    have_curl=yes
fi
```

`command -v` is POSIX and is the canonical check. `which` is an
external program with inconsistent behavior across systems (some
versions print to stdout regardless of presence; some return weird
exit codes). `type -P` is bash-specific. ShellCheck SC2230 flags
`which` usage and recommends `command -v`.

---

## 12. Path and PATH manipulation

The `PATH` environment variable controls command resolution. Mishandling
it is a recurring security and reliability footgun.

### 12.1 PATH at script start

The shell consults `PATH` (left-to-right) for any command that doesn't
contain a `/`. The classic bug:

```bash
#!/bin/sh
ls /tmp
```

If an attacker has prepended `~/evil` to `PATH` and placed an
executable named `ls` there, the script runs the attacker's `ls`.
The fixes:

- Use full paths in security-sensitive scripts: `/bin/ls /tmp`.
- Set PATH at script start: `PATH=/usr/local/bin:/usr/bin:/bin`.
- For setuid wrappers, refuse to execute if PATH is suspicious.

ShellCheck SC2123 flags assigning a single directory to `PATH`,
which it assumes is an accidental overwrite.

### 12.2 `/bin/sh` vs `/usr/bin/env bash` shebangs

`#!/bin/sh` — POSIX-only, portable across BSD/macOS/Linux/AIX.
`#!/bin/bash` — assumes bash at that exact path; fine on most Linux,
not safe on FreeBSD (where bash is `/usr/local/bin/bash`).
`#!/usr/bin/env bash` — POSIX way to look up bash via PATH; portable.
The latter is the bias for any new script that needs bash-specific
features. The pitfall: `env`-shebangs cannot take arguments on Linux
(`#!/usr/bin/env bash -x` fails; the kernel parses `bash -x` as a
single command name).

### 12.3 `command -v` vs `which` vs `type -P`

(See §11.5.) For detection, `command -v` is POSIX and reliable.

### 12.4 `cd` with no argument goes home

```bash
cd                               # goes to $HOME
cd "$1"                          # goes to $1
cd "$1" || exit 1                # goes to $1, or exits if $1 is bad
```

If `$1` is empty, `cd "$1"` is *not* `cd` (with no args); it is
`cd ""` (with an empty string), which current bash, dash and zsh treat
as a silent no-op (POSIX.1-2024 requires an error). The fix is to test
explicitly:

```bash
if [ -z "$1" ]; then echo "usage: $0 DIR" >&2; exit 1; fi
cd -- "$1"
```

The `--` prevents a `$1` that starts with `-` from being parsed as a
`cd` option (some shells have `-L`, `-P`, `-`, `-e`). ShellCheck SC2164
flags `cd` without `|| exit` / `|| return`.

### 12.5 The "I cd'd successfully so the next command operates in the right place" assumption

`cd build && make` is correct: `make` runs only if `cd build` succeeded.
`cd build; make` is wrong: `make` runs even if `cd build` failed,
which means it operates in the *previous* directory.

ShellCheck SC2164 covers exactly this: every `cd` should be followed by
`|| exit`, `|| return`, or appear in an `&&` chain.

### 12.6 `cd -` and PWD/OLDPWD

`cd -` jumps to `$OLDPWD`. `cd $OLDPWD` is equivalent but loses the
diagnostic print. The two variables `$PWD` and `$OLDPWD` are
shell-maintained. Modifying them by hand has no effect on the actual
process cwd (they are descriptive, not prescriptive).

---

## 13. Shellshock and the environment-as-attack-surface lesson

CVE-2014-6271 ("Shellshock") is the canonical case where a shell-language-
internal feature became a cross-language attack vector. The lesson
remains current: any place an environment variable crosses a trust
boundary is a footgun.

### 13.1 The CVE-2014-6271 mechanism

Bash exports shell functions through environment variables. The export
encoding stored a function definition as an environment variable
whose *value* began with `() { ... }`. When a new bash process
parsed the environment, it scanned each variable for the function-
definition prefix, and if it matched, evaluated the value as bash
code.

The Chazelas bug was that bash's parser didn't *stop* at the closing
`}` — it kept going. An attacker could set an environment variable
like:

```
MY_VAR='() { :; }; /bin/touch /tmp/pwned'
```

Any bash process that received this env var via fork-exec from a
parent that had set it (which includes CGI scripts, DHCP clients,
SSH `ForceCommand` sessions, and Git/Subversion restricted shells) would, at startup,
parse the env var, recognize the function-prefix, *and execute the
trailing command after the function definition*.

Stéphane Chazelas reported the bug privately to Chet Ramey on
2014-09-12. Public disclosure was 2014-09-24. The patch chain:

- **CVE-2014-6271** — original Shellshock disclosure; bash43-025
  patch by Chet Ramey, 2014-09-24.
- **CVE-2014-7169** — bypass of the first patch via incomplete
  parsing fix; bash43-026, 2014-09-26.
- **CVE-2014-7186** — additional out-of-bounds memory issue found
  by Florian Weimer (Red Hat); bash43-028.
- **CVE-2014-7187** — companion to -7186, off-by-one error in the
  parser.
- **CVE-2014-6277** — uninitialized-memory issue found in extended
  testing; bash43-029 / bash32-056.
- **CVE-2014-6278** — additional function-import bypass; bash43-030
  / bash32-057.

By 2014-10-05, the patch chain was complete. The post-Shellshock
norm is that bash function-export is restricted to environment
variables with the `BASH_FUNC_` prefix and `%%` suffix — a
namespace that explicit attackers cannot easily forge.

### 13.2 The lesson, restated

The Shellshock bug class is "an environment variable crosses a trust
boundary and is interpreted as code." The specific bash bug is patched;
the category recurs in Git hooks with attacker-influenced env; CI
pipelines that pass commit messages to shell `eval`-equivalents (GitHub
Actions `run:` blocks with `${{ github.event.head_commit.message }}` —
see `cicd_supply_chain_expertise.md`); DHCP clients; cron jobs that
inherit interactive env; Docker entrypoints that interpret CMD strings.

Structural defense: do not interpret env vars as code. Pass argv arrays
explicitly, or sanitize env at boundary (whitelist of variables, fixed
values for PATH, IFS, LC_*).

### 13.3 Bash arithmetic and `((...))` injection

```bash
((counter = $user_input + 1))
```

Inside `((...))`, the arithmetic parser supports indirect references
through `${!name}` and array subscripts that themselves can contain
command substitution: `a[$(touch /tmp/pwned)0]` triggers command exec
inside arithmetic. Fix: validate `$user_input` matches `^-?[0-9]+$`,
or use `expr` (far simpler parser). ShellCheck SC2076 flags a quoted
right-hand side of `=~`, which matches literally rather than as a regex.

---

## 14. Zsh-specific footguns

Zsh's expansion model is more elaborate than bash's, and its option
matrix (`setopt` and `unsetopt`) is larger. Most footguns are
porting-from-bash mistakes; a few are genuinely zsh-specific.

### 14.1 The `setopt` matrix

Zsh has on the order of 200 settable options. The load-bearing
ones for porting from bash:

- `SH_WORD_SPLIT` — enable bash-style word-splitting (off by default).
- `KSH_ARRAYS` — use 0-based indexing and bash-style `${arr[*]}`
  semantics (off by default; zsh defaults to 1-based).
- `BASH_REMATCH` — populate the `BASH_REMATCH` array for `[[ var =~ pat
  ]]` (off by default).
- `GLOB_DOTS` — include dotfiles in `*` expansion (off by default).
- `NULL_GLOB` — empty glob expands to nothing (off by default; zsh
  default is to error on no-match unless `NOMATCH` is unset).
- `RC_EXPAND_PARAM` — array expansion of `foo${arr}bar` distributes
  the surrounding text across each element (off by default).

The canonical zsh porting prelude:

```zsh
emulate -L bash
setopt SH_WORD_SPLIT KSH_ARRAYS BASH_REMATCH NULL_GLOB
```

`emulate -L bash` sets a long list of compatibility options scoped to
the current function (the `-L` means "local"). This is the safest way
to run a bash-style script under zsh.

### 14.2 Zsh prompt-expansion as RCE (CVE-2021-45444)

Zsh's `PROMPT_SUBST` enables parameter, command, and arithmetic
expansion inside prompt strings. CVE-2021-45444 (zsh < 5.8.1) was a
recursive PROMPT_SUBST bug: attacker-controlled prompt input (typically
a git branch name displayed via `%F`) could escape the prompt-expansion
context and execute. Attack vector: a malicious branch name (Git permits
embedded `$(...)`), cloned into a directory whose prompt displays the
branch.

Mitigations: update to zsh 5.8.1+; `setopt NO_PROMPT_SUBST` if not
needed; for Oh My Zsh / Powerlevel10k, ensure branch-name display
sanitizes `$()` and `` ` ``. Cross-link: `cicd_supply_chain_expertise.md`
— any CI that displays repository content (branches, commits, tags) in
an unsanitized shell context is a Shellshock-class vulnerability.

### 14.3 Glob qualifiers `(N)`, `(.)`, `(/)`

Zsh extends globs with parenthesized qualifiers:

```zsh
*(.)              # only regular files
*(/)              # only directories
*(N)              # NULL_GLOB for this glob only
*(m-1)            # modified less than 1 day ago
*(L+1024)         # larger than 1 KiB
```

Equivalent to inline `find`. Zsh-specific; non-portable. ShellCheck
SC1071 fires on an unsupported shebang such as zsh.

### 14.4 The ".zshrc runs every login" attack surface

Oh My Zsh, Prezto, and similar frameworks source community plugins on
every shell start, with full filesystem + network + ambient credentials.
A malicious plugin update is a developer-laptop supply-chain footgun.
Defenses: pin plugins to a commit; audit for `curl ... | sh` patterns;
treat `.zshrc` as security-sensitive in compromise investigations.
See `cicd_supply_chain_expertise.md` for the broader class.

### 14.5 `setopt EXTENDED_GLOB`

Adds `^pattern` (negation), `~` (set subtraction), `#` (repeat). Useful
but changes the literal-character interpretation for `^`, `~`, `#` in
glob contexts — a bash-to-zsh porting hazard.

---

## 15. Detection patterns

ShellCheck is the canonical static analyzer for bash and POSIX sh.
For shell-injection detection across language boundaries, Semgrep
is the canonical tool. Together they cover most of the footgun
catalog in §§2-14.

### 15.1 ShellCheck rule catalog

The full rule list lives at `shellcheck.net/wiki`. Rules cited
elsewhere in this document, indexed:

| Rule | Section | What it catches |
|------|---------|-----------------|
| SC1071 | §14.3 | Unsupported shell in shebang (e.g. zsh) |
| SC1083 | §3.4 | Literal `{`/`}` (missing `;` or unquoted) |
| SC2006 | §4.4 | Backticks instead of `$()` |
| SC2030, SC2031 | §9.2 | Variables modified inside pipe-fed loop |
| SC2035 | §3.1 | Glob as first argument without `./` or `--` |
| SC2046 | §2.7 | Unquoted command substitution |
| SC2076 | §13.3 | Quoted rhs of `=~` matches literally |
| SC2086 | §2.2 | Unquoted variable expansion |
| SC2095 | §7.3 | ssh stealing read-loop stdin |
| SC2103 | §4.2 | `cd` back instead of using a subshell |
| SC2104 | §9.4 | `break` in a function instead of `return` |
| SC2123 | §12.1 | Single directory assigned to `PATH` |
| SC2144 | §3.3 | `-e *.txt` not what you think |
| SC2155 | §6.1 | `local var=$(cmd)` masks exit status |
| SC2162 | §7.1 | `read` without `-r` |
| SC2164 | §12.5 | `cd` without `|| exit` |
| SC2184 | §8.2 | `unset arr[0]` glob-expansion |
| SC2230 | §11.5 | `which` instead of `command -v` |
| SC2294 | §11.1 | `eval` on an array or `"$@"` |

ShellCheck integrates with most editors, with most CI systems (via
GitHub Action or pre-commit hook), and as a standalone CLI. The
canonical setup for a new bash project is a `.shellcheckrc` at repo
root and a CI step that fails on any new finding.

### 15.2 Semgrep patterns for shell

Semgrep's `bash` language support is partial; `generic` or `regex` mode
is often more reliable. See the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the mode
tradeoff. Patterns worth encoding:

- `eval $...` — flag every `eval` of a variable.
- `${!...}` — flag bash-internal indirection; review for `declare -n`.
- Unquoted `$VAR` adjacent to `rm`, `cp`, `mv`, `chmod`, `chown`.
- `curl|wget ... | sh` — supply-chain footgun.
- `set -x` followed by `*TOKEN*`, `*SECRET*`, `*KEY*`, `*PASSWORD*`.

### 15.3 ShellCheck as a pre-commit hook

```yaml
- repo: https://github.com/koalaman/shellcheck-precommit
  rev: v0.10.0
  hooks:
    - id: shellcheck
```

False-positive rate is low enough that rule exclusions should be the
rare exception. ShellCheck reports SC1008 on unrecognized shebangs.

---

## 16. Defensive checklist and variant analysis

The shell-script auditor's mental checklist, condensed. Use this as
the §16 of `code_review_expertise.md` for shell scripts.

### 16.1 Fifteen-item review checklist

When auditing a shell script:

1. **Shebang declares the interpreter explicitly.** No bare scripts.
   `#!/usr/bin/env bash` for bash; `#!/bin/sh` for portable.
2. **Strict-mode prelude is present.** `set -euo pipefail` plus
   `IFS=$'\n\t'` for new scripts.
3. **Every variable expansion is quoted.** `"$var"` not `$var`.
   ShellCheck SC2086.
4. **Every command substitution is quoted.** `"$(cmd)"` not `$(cmd)`
   in argument positions. ShellCheck SC2046.
5. **`read` always uses `-r`.** ShellCheck SC2162.
6. **`for f in *.txt` uses `./` prefix or `--` end-of-options.**
   Filename-as-option-injection defense.
7. **Globs that may be empty are handled.** `shopt -s nullglob` at
   script top, or explicit existence check.
8. **`cd` is followed by `|| exit` or appears in an `&&` chain.**
   ShellCheck SC2164.
9. **Pipe-fed `while read` loops don't try to mutate parent-shell
   state.** Process substitution `< <(cmd)` or `done < file`.
10. **`eval` is absent or has a strong justification.** Indirect
    variable access uses `${!var}` or `declare -n`.
11. **`mktemp -d` + trap-EXIT cleanup for any tempfile usage.**
12. **`set -x` is disabled around secret-handling code.** Or the
    script does not handle secrets directly (passed via env, not
    stdout-echoed).
13. **PATH is explicitly set or commands use absolute paths in
    security-sensitive contexts.**
14. **Environment-variable-as-input is treated as untrusted.**
    Post-Shellshock norm; whitelist of vars at script start.
15. **The script passes ShellCheck with no exceptions, or every
    exception has a `# shellcheck disable=` line with comment
    justification.**

### 16.2 Variant analysis: alternative shells

- **dash** (Debian Almquist) — POSIX-only, fast, default `/bin/sh` on
  Debian/Ubuntu. Many bash-isms (`[[ ]]`, arrays, `${var^^}`, `mapfile`)
  absent; bash scripts fail with cryptic errors.
- **ksh93** (Korn Shell) — closer to POSIX than bash; arrays,
  associative arrays, floating-point arithmetic.
- **fish** — non-POSIX by design. Different variable, command-
  substitution, and control-flow syntax. Interactive-focused.
- **nu shell** — typed-record pipelines; structured data; different
  mental model.
- **Oils** (formerly Oil) — bash-compatible OSH + new YSH; Andy Chu.

Heuristic: if the shebang names a non-bash shell, treat it as a separate
language. This document covers bash, zsh, POSIX sh; rules apply loosely
to ksh93; rarely to fish, nu, or YSH.

### 16.3 The "is this script worth refactoring?" judgment call

A 50-line script with three quoting bugs is worth fixing. A 5000-line
script is worth rewriting in Python (or Ruby with `Open3`, or Go with
`exec`). Approximate threshold: 200+ lines, 5+ functions, 3+ nesting
levels. See `code_review_expertise.md` §16. The target languages still
require attention to the cross-language shell-injection rules in
`shell_injection_expertise.md`.

---

## 17. References

**Bash:**
- Chet Ramey, *Bash Reference Manual* — `gnu.org/software/bash/manual/`
- Chet Ramey, "Bash, the Bourne-Again Shell" (ROSE 94, Bucharest) — `tiswww.case.edu/php/chet/bash/rose94.pdf`
- bash CHANGES / NEWS files in the distribution

**Wooledge corpus:**
- BashFAQ — `mywiki.wooledge.org/BashFAQ`
- BashPitfalls — `mywiki.wooledge.org/BashPitfalls`
- BashGuide — `mywiki.wooledge.org/BashGuide`
- WordSplitting — `mywiki.wooledge.org/WordSplitting`
- IFS — `mywiki.wooledge.org/IFS`
- glob — `mywiki.wooledge.org/glob`

**ShellCheck:**
- `shellcheck.net` (web demo)
- `shellcheck.net/wiki` (per-rule documentation, SC0001-SC2300+)
- `github.com/koalaman/shellcheck` (source)
- Vidar Holen, "Lessons learned from writing ShellCheck" — `vidarholen.net/contents/blog/?p=859`

**Shellshock primary sources:**
- CVE-2014-6271, -6277, -6278, -7169, -7186, -7187 (MITRE / NVD)
- CISA Alert TA14-268A — `cisa.gov/news-events/alerts/2014/09/25/`
- OpenWall oss-security 2014 Q4 archive — `seclists.org/oss-sec/2014/q4/`
- David A. Wheeler, "Shellshock" — `dwheeler.com/essays/shellshock.html`
- Red Hat KB 1207723 — `access.redhat.com/solutions/1207723`

**Zsh:**
- Zsh Reference Manual — `zsh.sourceforge.io/Doc/Release/`
- Zsh FAQ §2.1 "Differences from sh and ksh" — `zsh.sourceforge.io/FAQ/`
- CVE-2021-45444 (NVD); Gentoo GLSA 202407-01 — `security.gentoo.org/glsa/202407-01`
- Peter Stephenson, Oliver Kiddle, Jerry Peek, *zsh: From Bash to Z Shell* (Apress, 2005)

**POSIX / historical:**
- POSIX.1-2024 Shell and Utilities — `pubs.opengroup.org/onlinepubs/`
- Sven Mascheck's Bourne-shell history — `in-ulm.de/~mascheck/bourne/`

**Cross-references in this repo:**
- `shell_injection_expertise.md` (the cross-language bug class — parent)
- `code_review_expertise.md` (candidate-point methodology)
- [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) (detection-rule authoring)
- `cicd_supply_chain_expertise.md` (CI/CD trust-boundary context)

---

*End of document.*
