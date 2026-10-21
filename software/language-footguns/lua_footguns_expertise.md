# Lua Behavioral Footguns — Embedded-Language Primitives That Are Unsafe by Default
## Synthesized from the Lua/PUC-Rio team, LuaJIT and Luau maintainers, the Lua sandbox-escape research corpus, and the institutional advisories that catalog Lua-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. Part of the
> **language-specific behavioral footguns** class (siblings:
> `javascript_node_footguns_expertise.md`,
> `csharp_dotnet_footguns_expertise.md`, `java_footguns_expertise.md`,
> `php_footguns_expertise.md`, `python_footguns_expertise.md`,
> `ruby_footguns_expertise.md`, `go_footguns_expertise.md`,
> `rust_footguns_expertise.md`, `kotlin_footguns_expertise.md`,
> `scala_footguns_expertise.md`, `swift_footguns_expertise.md`,
> `shell_footguns_expertise.md`, `sql_dialect_footguns_expertise.md`,
> `powershell_footguns_expertise.md`). Lua occupies a narrower niche
> than its siblings: a small embeddable extension language, not a
> general-purpose application platform. Almost every Lua deployment
> in the wild lives inside a host process — Wireshark, Redis,
> OpenResty/nginx, Roblox/Luau, World of Warcraft, neovim, Adobe
> Lightroom, Factorio, Garry's Mod, Domoticz, embedded firmwares. The
> behavioral footgun class that matters for Lua is therefore not
> "this builtin shells out" (it has very few builtins) but "the host
> reached for Lua expecting a sandbox, did not get one, and ships an
> escape primitive by default."
>
> **Researchers:**
> - **Roberto Ierusalimschy** — Co-creator of Lua at TeCGraf, PUC-Rio
>   (1993, with Luiz Henrique de Figueiredo and Waldemar Celes); full
>   professor of informatics, PUC-Rio. Author of *Programming in Lua*
>   (four editions) and "The Evolution of Lua" (HOPL III, 2007);
>   creator of LPeg. The load-bearing primary source for "Lua is an
>   embeddable extension language, not a security boundary."
> - **Luiz Henrique de Figueiredo** — Co-creator of Lua at TeCGraf;
>   maintains the Lua reference distribution at
>   `web.tecgraf.puc-rio.br/~lhf/`. Canonical source for the
>   reference implementation's release engineering and the bug-fix
>   stream at `lua.org/bugs.html`.
> - **Waldemar Celes** — Co-creator of Lua at TeCGraf; co-recipient
>   with Ierusalimschy and de Figueiredo of the Pedro Ernesto medal
>   for the creation of Lua.
> - **Mike Pall** — Original author of LuaJIT (luajit.org). Canonical
>   primary source for the position that the
>   only viable sandbox for Lua is a process-level boundary, not
>   in-VM scoping tricks. The same argument is the foundation of the
>   JS-sandbox corpus; cross-cited in `js_sandbox_escape_expertise.md`.
> - **André Murbach Maidl** — PhD researcher (PUC-Rio LabLua),
>   co-author of "Typed Lua: An Optional Type System for Lua"
>   (Dyla 2014) and "A Formalization of Typed Lua" (DLS 2015). The
>   Typed Lua → Pallene → Luau lineage is the academic engagement
>   with making Lua a language one can reason about formally — and
>   indirectly with the sandbox question.
> - **Samuel Groß (saelo)** — Author of "Pwning Lua through 'load'"
>   (saelo.github.io). Canonical writeup on Lua bytecode
>   exploitation: out-of-bounds LOADK to forge TValues, fake
>   string/table objects for read/write, setjmp-via-coroutine to arbitrary
>   native code. Original 33C3 CTF "read-eval-pwn loop" author.
> - **Peter Cawley (corsix)** — LuaJIT internals researcher; "Malicious
>   LuaJIT bytecode" (corsix.org) and "Exploiting Lua 5.1 on 32-bit
>   Windows." Primary source on LuaJIT bytecode-loading as an RCE
>   primitive against any process consuming untrusted bytecode.
> - **Ben Murphy (benmmurphy)** — Reporter of the original 2015 Redis
>   EVAL Lua sandbox escape. The disclosure that established the
>   pattern CVE-2022-0543 replays via Debian/Ubuntu packaging.
> - **The Roblox Luau team** — Maintainers of Roblox's typed Lua
>   fork (luau.org, github.com/Roblox/luau); authors of
>   `luau/SECURITY.md`. The only major Lua dialect designed with
>   sandboxing as a first-class requirement: bytecode loading
>   removed, debug library scoped down, FFI absent, per-script
>   globals.
> - **The lua-users wiki SandBoxes corpus** — Institutional;
>   `lua-users.org/wiki/SandBoxes` is the closest thing Lua has to
>   an OWASP-style maintained checklist of unsafe primitives.
>
> **Institutional contributors:** PUC-Rio LabLua; LuaJIT project;
> Roblox Luau project; Redis Inc. security team; OpenResty;
> Wireshark Foundation; Mozilla Services (lua_sandbox); kikito's
> `lua-sandbox`; MITRE CWE (913, 94, 95, 915); Snyk Vulnerability
> DB; GitHub Advisory Database; the `lua-l` mailing list archive;
> HackTricks Lua sandbox-escape page; Trail of Bits.
>
> **What this doc is NOT:** not a Lua language tutorial, not a
> replacement for cross-language bug-class guidance. It is the
> Lua-specific layer beneath cross-language audit heuristics — the
> embedding-host layer that determines whether shipping Lua to your
> users is a feature or an RCE.

Cross-links: `js_sandbox_escape_expertise.md` (the parent "in-process
sandbox is structurally impossible" lineage; Mike Pall's argument
applies to JS one-for-one and the reverse is also true);
`c_cpp_footguns_expertise.md` (LuaJIT FFI inherits every C undefined
behavior); `code_review_expertise.md` (auditing host applications
that embed Lua); `semgrep_rule_authoring.md` (detection rules for the
unsafe-builtin and unsafe-host-binding patterns);
`redos_algorithmic_dos_expertise.md` (Lua patterns are not PCRE but
LPeg can be); `deserialization_expertise.md` (Lua bytecode loading is
the deserialization-class primitive for Lua);
`detection_engineering_expertise.md` (auditing for unsafe-Lua-on-host
patterns at scale).

---

## 1. The behavioral-footgun framing

### 1.1 Lua's niche is "embeddable extension language"

Lua was designed in 1993 at TeCGraf, PUC-Rio, by Roberto
Ierusalimschy, Luiz Henrique de Figueiredo, and Waldemar Celes, as
the successor to an in-house configuration language called SOL
("Simple Object Language") for Petrobras-funded data entry and
report-generation tools. The design constraint was explicit: a small
language that embeds into a host C application, provides a
configuration / scripting surface, and stays out of the way.

The footgun lineage falls out of this design. Lua ships as a
`liblua.a` you link into your application. The host chooses which
builtins are exposed, which globals are bound, what filesystem
access exists. The reference manual covers the default state —
every standard library available, every metatable manipulable,
every function dumpable to bytecode — but the host is the final
authority. When a host takes the defaults and also accepts
user-supplied Lua, the host has effectively shipped arbitrary code
execution.

Almost every Lua-related CVE in the public record traces to this
contract violation. The host wanted "user-supplied configuration"
or "user-supplied plugin"; the host got "user-supplied RCE" because
the default Lua surface is not a sandbox. Wireshark, Redis,
OpenResty, Roblox (pre-Luau), Factorio, and Garry's Mod have each
shipped at least one disclosure here.

### 1.2 "Lua is small and simple" collides with "sandbox escape is well-documented"

The Lua reference manual is approximately 100 pages. The Lua source
distribution is approximately 30,000 lines of C — small enough that
"I'll just read the source" is a serious audit strategy. This is a
real strength: teachable in an afternoon, shippable in a kilobyte-
class binary.

But "small" is not "sandboxable." A small language that gives
every guest function transparent metatable access, that ships
`string.dump` and `load` as builtins, and that has well-documented
bytecode-level exploitation primitives is not safer than a larger
language with explicit privilege gates. It is precisely the absence
of such gates — the default-permissive model — that makes Lua's
small surface deceptive.

### 1.3 Cross-link to the JS-sandbox lineage

Mike Pall's argument against in-VM sandboxing of LuaJIT is quoted
at length in `js_sandbox_escape_expertise.md` because it generalizes
to every fast language with a runtime native-code generator. The
Lua-specific consequences:

- **Bytecode loading is a category-of-attack primitive.** Via
  `loadstring(string.dump(f))` in Lua 5.1, `load(bytecode)` in 5.2+,
  or LuaJIT's `-b` mode, accepting untrusted bytecode
  collapses the sandbox boundary.
- **The debug library is escape-as-a-feature.** `debug.getupvalue`
  /`debug.setupvalue` walk closure captures; `debug.sethook`
  intercepts arbitrary calls; `debug.getinfo` re-enables identifier
  lookup even when `_G` is hidden.
- **Metatables are unforgeable in the default configuration.**
  Without `__metatable` lockout, `getmetatable(x)` returns the
  metatable; `rawget`/`rawset` bypass protective metamethods.
- **`_G` is a single table reachable by name.** Every unqualified
  global resolves through `_ENV` (Lua 5.2+) or the function
  environment (5.1 via `setfenv`/`getfenv`); both are walkable.

### 1.4 What the doctrine says

The lua-users SandBoxes position:

- The default Lua runtime is not a sandbox. Exposing
  `load`/`loadstring` to user input ships RCE.
- The only known-good approaches are (a) bytecode validation +
  strict allowlist of language features (Roblox Luau, requires a
  fork), or (b) process-level isolation. Anything in between is a
  quarterly-CVE pipeline.

---

## 2. Globals are public by default

### 2.1 The `local` keyword and the omission footgun

Lua's variable semantics: every assignment to a bare identifier
creates a global (or reassigns an existing global). The `local`
keyword introduces a lexical local; without it, the assignment
escapes the function's scope.

```lua
function compute(x)
    result = x * 2   -- accidentally global
    return result
end
```

In every other mainstream scripting language with a declaration
form (JS `"use strict"`, Python `global`/`nonlocal`, Ruby sigils),
default binding distinguishes lexical from global scope. Lua does
the opposite: omission of `local` is the global binding. The HOPL
III rationale was that configuration-language one-liners should
not require declarations; production code by application
developers consistently leaks identifiers.

Common manifestation: a script declares a variable named `debug`
without `local`, which shadows the standard `debug` table for the
rest of the process; a typo creates a new global at the call site
rather than failing.

Detection: `luacheck` reports "setting non-standard global
variable" by default. Lua 5.5 (released December 2025) introduces
optional `global` declarations after decades of community pressure;
backporting is impossible — the discipline must come from the
linter.

### 2.2 `_G` and `_ENV`

Lua 5.1 exposes `_G` plus `getfenv`/`setfenv`. Lua 5.2+ replaces
those with the `_ENV` upvalue: every unqualified name resolves to
`_ENV.name`, default `_ENV` is `_G`.

Sandboxing implication: setting `_ENV` to a restricted table on a
`load`'d chunk *appears* to restrict reach, but the restriction is
only as good as the metatable contract on the replacement. If the
replacement uses `__index = _G` for fallthrough, the restriction
is cosmetic. If it's a flat copy of allowlisted builtins, the
guest can still reach `debug.*`, `string.dump`, `load`,
`package.loadlib`, the metatable accessors — all escape primitives.

```lua
-- Lua 5.2+: appears sandboxed; is not
local restricted = { print = print, string = string, math = math }
local f = load(user_code, "@user", "t", restricted)
f()
-- guest can:
--   string.dump(some_function)        -> bytecode
--   getmetatable("").__index          -> string library reachable
```

Lua 5.1's `setfenv(0, ...)` modifies the thread-level environment;
`setfenv(2, ...)` walks up to the caller. The 5.2 redesign was
specifically motivated by the difficulty of reasoning about
`setfenv`'s scope.

### 2.3 The "wrote a sandbox, forgot the strings" pattern

```lua
local sandbox = { print = print }
local chunk = load("return getmetatable('').__index", "@c", "t", sandbox)
local string_lib = chunk()
-- string_lib is the host-realm string library with .dump, .rep, .format
```

Fix: `debug.setmetatable("", nil)` *before* constructing the
sandbox, or use a fork (Luau) where the string metatable is
per-state and lockable.

---

## 3. Metatables, `__index`, `__newindex`, and the `__metatable` lockout

### 3.1 The metamethod-as-bypass pattern

Every Lua table has a (possibly nil) metatable. `__index` defines
fallback for missing-key reads; `__newindex` defines new-key write
handler. A guest controlling the metatable of any reachable value
controls property-access behavior on that value.

```lua
local guard = setmetatable({}, {
    __index    = function(_, k) error("read disallowed: " .. k) end,
    __newindex = function(_, k, v) error("write disallowed: " .. k) end,
})
```

Foundation of every defensive-sandboxing implementation. Defeated
by `rawget`/`rawset` (bypass metatable lookup) and by
`debug.getmetatable` (bypasses `__metatable` lockout).

### 3.2 The metamethod surface

Lua exposes metamethods for every operator: `__call` (callable
table), `__concat`, `__add`/`__sub`/`__mul`/`__div`/`__mod`/
`__pow`/`__unm`, `__eq`/`__lt`/`__le`, `__tostring`, `__len`,
`__pairs` (5.2+), `__close` (5.4+).

Sandboxing implication: any value the guest constructs can execute
guest-controlled code on operations the host did not anticipate.
A host that calls `tostring(x)` re-enters guest code via
`x.__tostring(x)` if `x` has that metamethod set.

### 3.3 The `__metatable` lockout and its bypass

```lua
setmetatable(t, { __metatable = "locked" })
getmetatable(t)   -- returns "locked"; setmetatable(t, ...) raises
```

`debug.getmetatable` bypasses `__metatable`. `debug.setmetatable`
is the write primitive — `debug.setmetatable("", mt)` rewrites
the metatable for *every* string in the running state, including
host-side strings. Any sandbox that does not remove `debug.*` is
defeated.

### 3.4 The "I wrote a sandbox but did not lock down metatables" pattern

Recurring failure mode:

1. Hide `os`, `io`, `package`, `debug` from `_ENV`.
2. Replace `_G` with allowlisted builtins.
3. Forget to `debug.setmetatable("", nil)` to detach the shared
   string metatable.
4. Forget to remove `getmetatable`/`setmetatable` from the
   allowlist.
5. Guest runs `getmetatable("").__index` → full string library →
   `string.dump` → bytecode-loading chain (§5).

Mitigation: remove or wrap every intrinsic metatable accessor —
`getmetatable`, `setmetatable`, `rawget`, `rawset`, `rawequal`,
`rawlen`, plus the entire `debug` table (`getmetatable`,
`setmetatable`, `getupvalue`, `setupvalue`, `getlocal`, `setlocal`,
`sethook`, `getinfo`, `getregistry`, `upvaluejoin`). Luau's
sandbox documentation (`luau.org/sandbox`) documents the analogous
restrictions.

---

## 4. `loadstring`, `load`, `loadfile`, `dofile`

### 4.1 The runtime-eval surface

Lua's runtime-eval primitives:

- **`loadstring(s)`** (Lua 5.1) — Compile `s` as a Lua chunk and
  return the compiled function. Does not execute.
- **`load(s_or_function, chunkname, mode, env)`** (Lua 5.2+) —
  Same, with an optional `env` parameter to set `_ENV` for the
  loaded chunk and a `mode` parameter ("t" for text-only, "b"
  for bytecode-only, "bt" for both).
- **`loadfile(path, mode, env)`** — Same, but read from a file.
- **`dofile(path)`** — Read, compile, and immediately call.

Each of these is a runtime eval primitive. The `mode` parameter
in Lua 5.2+ is the single most security-relevant addition:
`mode = "t"` rejects bytecode-mode chunks, eliminating the
bytecode-exploit surface documented in §5. **A defensive
embedding must pass `mode = "t"` explicitly.** The default for
`load(s)` without `mode` is `"bt"` — both text and bytecode are
accepted.

### 4.2 The "I'll just use `load` with a restricted environment" pattern

```lua
local restricted_env = { print = print, string = string,
                         math = math, table = table }
local chunk, err = load(user_code, "@user", "t", restricted_env)
if chunk then chunk() end
```

The canonical "I have a sandbox" code from tutorials and Stack
Overflow. Not a sandbox:

- `string`, `math`, `table` are host-realm tables. The guest
  walks `getmetatable(string)` to reach the host.
- `string.dump` and `string.rep` are inside `string` (dump →
  bytecode chain; rep → DoS).
- Metatables of values inside the env are walkable.

Mozilla `lua_sandbox` and `kikito/lua-sandbox` are the more
defensible versions: explicit allowlist construction +
instruction-count debug hook + (kikito) a README warning that it
"does not provide protection against malicious users." The README
warning is load-bearing.

### 4.3 `loadfile` and `dofile` against guest-controlled paths

`loadfile(user_path)`/`dofile(user_path)` is the filesystem
equivalent of `load(user_string)`. Recurring pattern: host loads
plugins from `~/.appname/plugins/`, the directory is writable by
guest, guest drops a malicious `.lua`, next startup loads it.
Wireshark Lua plugins, OpenResty `init_by_lua_file`, Garry's Mod
content servers historically fit this shape.

Mitigation: never `loadfile`/`dofile` a guest-controlled path. If
plugins are a feature, allowlist directories + signature/hash
verify + process-level isolation.

---

## 5. Bytecode loading and the canonical sandbox-escape corpus

### 5.1 `string.dump(f)` → `load(bytecode)`

`string.dump(f)` serializes a Lua function (including its
upvalues and bytecode body) to a binary string. `load(s)` with
a binary string accepts it as a bytecode chunk and returns a
loadable function. The combination is the foundation of the
bytecode-attack class.

The PUC-Rio Lua VM does not validate the integrity of binary
chunks loaded via `load`. The reference manual (Lua 5.4
manual §6.1) explicitly documents this:
> "Lua does not check the consistency of the code inside binary
> chunks; running maliciously crafted bytecode can crash the
> interpreter."

The maximalist reading: crafted bytecode produces type
confusions in the VM's opcode handlers and reaches arbitrary
native code execution. The minimalist reading: even crashing
the interpreter is a DoS primitive against any service that
loads guest-supplied bytecode.

### 5.2 The Saelo "Pwning Lua through load" lineage

Samuel Groß's canonical writeup at
`saelo.github.io/posts/pwning-lua-through-load.html`. Chain:

1. **Out-of-bounds LOADK index.** LOADK loads a constant at a
   fixed index; crafted bytecode supplies an OOB index that
   reads adjacent heap memory as a `TValue*`.
2. **Constant-table spray.** Allocate strings shaped like valid
   TValues; allocator placement makes the OOB load return a
   forged TValue.
3. **Fake string and table objects.** A forged string with a huge
   length yields memory read; a forged table whose array pointer is
   attacker-chosen yields memory write.
4. **setjmp-via-coroutine arbitrary call.** Fake jmpbuf reached
   through a coroutine that yields after writing it; controlled
   `longjmp` lands attacker-chosen rip/rsp.

Lesson: untrusted bytecode is not a hardening problem, it is a
pipeline to remove. Roblox Luau removed `string.dump` and
bytecode loading entirely; corsix.org documents the equivalent
surface in LuaJIT (different format, same consistency-check
absence).

### 5.3 Real-world CVE corpus

**CVE-2022-0543** (Redis Lua sandbox escape, Debian/Ubuntu).
Upstream Redis statically links a stripped Lua without
`luaopen_package`/`luaopen_os`. Debian/Ubuntu dynamically link a
system Lua that retains them. Attacker reaches `package.loadlib`
and can load arbitrary libraries.
KEV catalog (CISA), Metasploit
`redis_debian_sandbox_escape`. DSA-5081, USN-5316-1.

**benmmurphy 2015 Redis EVAL escape.** Original disclosure
establishing the surface CVE-2022-0543 replays.

**CVE-2018-1999023 (Wesnoth).** Lua engine sandbox escape via
untrusted bytecode, reachable through saved games, network games,
replays and player content; fixed in Wesnoth 1.14.4.

**Factorio (memorycorruption.net, 2024).** CVE-2024-39840: a
malicious server could run code on clients via a custom map by
abusing Lua base functions that run bytecode; fixed in 1.1.101.

**Wireshark user-Lua-blocked-as-root.** With
`run_user_scripts_when_superuser` set to false in `init.lua`,
Wireshark running as (setuid) root does not load user Lua scripts.

### 5.4 The `setfenv(0, ...)` cross-thread escape (Lua 5.1)

`setfenv(0, t)` sets the current thread's global environment.
`setfenv(2, ...)` walks up the stack to the caller. A sandboxed
5.1 coroutine with `setfenv` reachable can rewrite `_G` for the
rest of the host's execution. The 5.2 redesign removed
`setfenv` because the Lua team found it too dynamic: any function
that can call another can change its environment.

---

## 6. Numeric semantics across Lua versions

### 6.1 Lua 5.1 / 5.2: single number type

Lua 5.1/5.2 expose a single numeric type (`number`), internally
double-precision float. `2^53 + 1 == 2^53` because the mantissa
is 52 bits and there is no integer subtype to detect the loss.
Array-indexing semantics follow float equality; `a[1.0]` and
`a[1]` and `a[1 + 1e-16]` may or may not refer to the same slot.

### 6.2 Lua 5.3+: integer subtype

Lua 5.3 introduced the integer subtype. `math.type(x)` returns
`"integer"`, `"float"`, or nil. Numeric constants with radix
point or exponent denote float; otherwise integer. Integer
overflow wraps modulo 2^64. Audit footgun: 5.1/5.2 code ported
to 5.3+ may exhibit different overflow behavior on what looks
like the same source.

### 6.3 `tonumber` edge cases

`tonumber("0x10") = 16` (hex). `tonumber("0e1") = 0` (scientific).
`tonumber("0x0e+1") = nil` (parse ambiguity — `0x0E` is hex 14,
`+1` is the next token). Host applications passing user strings
through `tonumber` should whitelist accepted formats explicitly.

### 6.4 Float-as-array-key

`a[1/0]` (positive infinity) is a valid table key; `a[0/0]` (NaN)
is not — the manual allows any value as a key except nil and NaN.

---

## 7. String operations, Lua patterns, and LPeg

### 7.1 Lua patterns are not PCRE

`string.find`/`match`/`gmatch`/`gsub` use Lua patterns, not PCRE:

- **Escape:** Lua `%`, PCRE `\`.
- **Classes:** `%a`/`%w`/`%s`/`%p`/`%c`/`%d`/`%x` (uppercase
  negates). Lua's `%w` excludes `_`; PCRE's `\w` includes it.
- **No alternation.** No `|`. `%b()` (balanced-pair) is
  Lua-specific.
- **Lazy quantifier.** `-` is shortest-match; `*`/`+` greedy;
  `?` optional.
- **No nested quantifiers.** Load-bearing for ReDoS — Lua
  patterns disallow `(a+)+`-style catastrophic backtracking.

ReDoS is less likely in Lua patterns than in PCRE-based
languages, but not impossible: `string.gsub(huge_string, "x*",
"y")` can be quadratic, and `string.rep(s, huge_n)` is a direct
DoS regardless of patterns. See `redos_algorithmic_dos_expertise.md`.

### 7.2 LPeg

`LPeg` (Ierusalimschy, `lua.org/lpeg/`) implements parsing
expression grammars — unambiguous by construction, no
backtracking explosion. Recommended for non-trivial parsing.
Own footgun surface: stack overflow on deep recursion,
exponential capture-list on pathological patterns.

### 7.3 `string.format` is not a C-class format-string attack

Lua's `string.format` is a restricted `printf` subset: no `%n`
(write-to-pointer), no width-specifier-pointer ambiguity.
Guest-controlled formats can still crash on type mismatch or
leak numeric representations through `%g`/`%a`; width and
precision are limited to two digits.

### 7.4 `string.rep(s, n)` DoS

Allocates `len(s) * n` bytes in one call. Cap both arguments.

---

## 8. `pcall`, `xpcall`, and error-handling discipline

### 8.1 The `pcall` protected-call protocol

`pcall(f, ...)` returns `(true, results...)` or `(false, err)`.
`err` is whatever was passed to `error()` — string by default, but
`error({...})` passes any guest-constructed value. A host that
logs `err` must not assume string; `error({__tostring = function()
... end})` re-enters guest code on the host's `tostring(err)`.

### 8.2 `xpcall(f, handler, ...)`

The handler runs *before* the stack unwinds — meaning
`debug.traceback()` can capture the full stack including local
variables. Guest-supplied handler + reachable `debug` library =
read-anywhere primitive over the caller's stack frames.
Load-bearing reason to remove `debug` entirely from a sandbox.

### 8.3 The "silent failure" anti-pattern

```lua
local ok = pcall(critical_operation)
-- ok discarded; error dropped
```

Equivalent to `try {} catch {}` in C++ or `except: pass` in
Python. Audit for security-relevant paths that silently swallow.

### 8.4 `assert(condition, msg)` shortcut

`assert(condition, msg)` raises `error(msg)` when `condition` is
falsey. Footgun: `assert(parse_user_input())` where the parser
returns `(value, err)` propagates `err` (guest-controlled) to the
host's caller log — a log-spoofing primitive.

### 8.5 Lua 5.4 `<close>` variables

`__close` metamethods run on scope exit. Guest values with
`__close` re-enter guest code on every host-side scope exit
holding the value. Nested errors inside `__close` propagate
normally; outer `pcall` wraps it but must handle the nested case
gracefully.

---

## 9. Coroutines and concurrency-like

### 9.1 Cooperative scheduling, not preemption

Lua coroutines are stackful asymmetric with cooperative
scheduling. Only `coroutine.yield` or normal completion returns
control. A guest coroutine that omits yield runs forever; the
host's only options are (a) instruction-count debug hook that
yields automatically (kikito 500K-instruction default),
(b) tear down the Lua state, or (c) process-level isolation.
Bounded-time evaluation must be enforced externally.

### 9.2 The "coroutine leaks state" pattern

A coroutine created and resumed but never resumed to completion
holds its stack frame, locals, upvalues, and captured-table
references. Long-running Lua state with this pattern is a memory
leak and an information leak via `debug.getregistry()`. Lua 5.4
`coroutine.close(co)` releases stuck coroutines; track and close
every created coroutine on host-side cancellation.

### 9.3 LuaJIT FFI + coroutines + threading

LuaJIT issue #186 asked how the FFI behaves when calling the Lua/C
API on other `lua_State`s; it was closed as invalid — the FFI
treats those as ordinary C functions.
Recurring failure mode: FFI registered into guest scope from a
host callback produces a cross-thread arbitrary-code primitive.

---

## 10. LuaJIT FFI

### 10.1 The `ffi.cdef` declarative-binding model

LuaJIT's Foreign Function Interface (FFI) library (Mike Pall's
design) allows Lua code to declare C types and function
prototypes via `ffi.cdef[[ ... ]]` and call them directly
through `ffi.C` (the default-symbol table; `ffi.load(name)`
for explicit shared-library loading).

```lua
local ffi = require("ffi")
ffi.cdef[[
    int system(const char *command);
]]
ffi.C.system("rm -rf /")
```

There is no privilege check, no allowlist, no mode flag. If
`require("ffi")` is reachable from the guest, the guest has
direct access to libc, to every dynamically-loaded library, to
the Windows API on Windows hosts. **FFI is full sandbox escape
by design.** This is not a CVE; this is the documented contract.

LuaJIT does not ship a "sandboxed FFI mode"; the LuaJIT FAQ calls
the FFI library inherently unsafe and says the only promising
approach is to sandbox Lua code at the process level, not the VM
level.

### 10.2 The escape-by-design lineage

LuaJIT sandbox + `ffi` reachable = ~five lines to RCE:

1. `ffi.cdef` `mprotect` (POSIX) or `VirtualProtect` (Windows)
   plus `mmap`/`VirtualAlloc`.
2. Allocate executable-writable memory.
3. Write shellcode.
4. `mprotect(buf, len, PROT_EXEC | PROT_READ)`.
5. `ffi.cast` to function pointer; call.

Treat exposing `ffi` to user-supplied scripts as equivalent to
shipping `Function` to a JS sandbox.

### 10.3 `ffi.cast` and `ffi.new`

`ffi.cast("uintptr_t *", lua_table)` gives a pointer into the
Lua heap; the guest walks VM internals to reach primitives.
`ffi.new("char[1024]")` allocates uninitialized C memory mutable
by anyone holding the cdata reference.

Cross-link: `c_cpp_footguns_expertise.md` — LuaJIT FFI inherits
every C UB class (use-after-free, double-free, type confusion,
buffer overflow).

---

## 11. Embedding-specific footguns

### 11.1 Wireshark Lua

Wireshark embeds Lua for protocol dissector scripting. The
Wireshark documentation (Chapter 12 of the Developer's Guide,
`wireshark.org/docs/wsdg_html_chunked/wsluarm.html`) documents
the `init.lua` configuration file and the `enable_lua` /
`disable_lua` variables.

Security-relevant behavior:

- **Root-detection-blocks-user-Lua.** When
  `run_user_scripts_when_superuser` is false, Wireshark run as
  (setuid) root does not load user Lua scripts (personal plugin
  directory, `-Xlua_script`, the Lua Evaluate menu); this is not
  checked on Windows.
- **`disable_lua` deprecation.** `disable_lua` (used by
  Wireshark 2.6 and earlier) is deprecated in favor of `enable_lua`; if both are present,
  `disable_lua` is ignored. Configuration that relies on the
  deprecated variable silently has no effect.
- **Dissector chaining.** Lua dissectors register against
  protocol fields and can run on every captured packet — a
  high-volume path. A malicious or buggy dissector can DoS a
  capture session or worse.

### 11.2 Redis Lua scripting

Redis exposes Lua scripting via `EVAL`, `EVALSHA`, and
`FUNCTION` commands. The Redis Lua API reference
(`redis.io/docs/latest/develop/programmability/lua-api/`)
documents the available libraries.

Upstream Redis statically links a *stripped* Lua: `package` is
not exposed and `os` is limited to `os.clock()` (since 7.4). EVAL
scripts see only `string`, `math`, `table`, `os.clock`, `struct`,
`cjson`, `cmsgpack`, `bit`, and the Redis-specific
`redis.call`/`redis.pcall` functions.

The CVE-2022-0543 vulnerability is the canonical example of
what happens when downstream packaging breaks this contract:
Debian/Ubuntu linked Redis against a dynamic system Lua that
*did* expose `package`, and any Redis with network exposure
became an RCE primitive. The disclosure cycle, the KEV catalog
inclusion, and the patch lineage (DSA-5081, USN-5316-1)
together establish the canonical "your sandbox is your binary,
not your code" lesson.

### 11.3 Roblox Luau

Roblox's Luau (`luau.org`, `github.com/Roblox/luau`) is the
typed Lua dialect Roblox uses for gameplay scripting. Luau's
sandbox documentation (`luau.org/sandbox`) describes the design:

- **Bytecode loading removed.** No `string.dump`, no `load` on
  bytecode. Source-level loading only.
- **Per-script global table.** Each script gets a fresh global
  table whose `__index` points to the shared base globals.
  Writes to globals are per-script and do not leak to peers.
- **Debug library restricted.** Most of `debug` is removed; only
  `debug.traceback` and `debug.info` remain.
- **FFI not exposed.** Luau does not include LuaJIT's FFI; the
  guest cannot reach C code outside the host's exposed
  surface.

Luau represents the maximum effort to make a Lua-dialect
sandbox actually defensible. The cost is a Lua fork, a custom
bytecode format, and a multi-year engineering investment.
Embedders that genuinely need to run adversarial Lua should
consider Luau or process-isolation; nothing in between has held
up under sustained adversarial pressure.

### 11.4 OpenResty / nginx-lua

OpenResty embeds LuaJIT into nginx via `lua-nginx-module`. Lua
phases (`access_by_lua`, `content_by_lua`, `init_by_lua`,
`body_filter_by_lua`, etc.) run at nginx lifecycle points.

Security-relevant primitives:

- **`ngx.location.capture`** — Subrequest to another location.
  User-controlled target = SSRF. CVE-2020-11724 documents the
  HTTP-request-smuggling angle (OpenResty before 1.15.8.4). See `http_web_security.md`.
- **`ngx.exec`** — Internal redirect; user-controllable target
  is an authorization-bypass primitive.
- **`share_all_vars`** — Documented "considered
  harmful"; shares parent-request variables with subrequest,
  leaking attacker-controlled variables into authorization
  context.
- **`init_by_lua_file`** — Loaded once per worker startup;
  attacker-writable referenced file = persistence.
- **`content_by_lua_block`** — Inline Lua in nginx config;
  user-controllable configs (multi-tenant nginx-as-a-service)
  mean user-controllable Lua.

Internet-facing + web-server privileges + Lua = highest-
sensitivity Lua embedding. Strict posture: no Lua from
user-writable paths, no user-input `ngx.location.capture`
targets, no `share_all_vars`, no nginx-as-root with Lua phases.

### 11.5 neovim Lua

neovim's `vim.uv` exposes libuv bindings for filesystem,
networking, and process management. Doctrine: **Lua in neovim
is the user**, not a sandbox. Plugins run with full filesystem
access, `vim.uv.spawn`, `vim.uv.tcp_connect` — by design.

Audit implication is supply chain: lazy.nvim/packer.nvim/
vim-plug load Lua from git clones; a compromised upstream
ships RCE on every plugin update. Cross-link
`cicd_supply_chain_expertise.md`.

### 11.6 Game-engine Lua (WoW, GMod, Factorio, Domoticz)

Common patterns:

- **Untrusted addon distribution.** CurseForge/GitHub downloads
  run with full engine-API and often full system reach.
- **Bytecode-loading via mod content.** Factorio (2024
  memorycorruption.net disclosures), Garry's Mod historically.
- **Anti-cheat circumvention via sandbox escape.** Pre-Luau
  Roblox cheat corpus is the prototype; the Luau move was
  significantly motivated by closing this surface.

Pattern: a Lua-scripted game that accepts user-distributed mods
has shipped RCE against every player who installs one.

---

## 12. Detection patterns and Semgrep rule sketches

### 12.1 Reachable unsafe builtins inside a sandbox context

Detection target: the `load(USER, ...)` and `loadstring(USER)`
patterns where `USER` is a tainted input. Semgrep YAML sketch:

```yaml
rules:
  - id: lua.unsafe-load-of-tainted-input
    languages: [lua]
    severity: ERROR
    message: |
      load()/loadstring()/loadfile()/dofile() with tainted input
      produces arbitrary code execution. If a sandbox is intended,
      use load(s, name, "t", restricted_env) with mode "t" only,
      strip debug/ffi/package/string.dump from the env, and
      detach the string metatable. Per the lua-users SandBoxes
      doctrine, this is insufficient for truly adversarial input.
    pattern-either:
      - pattern: load($X)
      - pattern: loadstring($X)
      - pattern: loadfile($X)
      - pattern: dofile($X)
```

Refinements: require `$X` to derive from a tainted source
(HTTP body, file, network read); whitelist `load($X, ..., "t",
...)` only if the env is also restricted; flag `load($X, ...,
"bt", ...)` and `load($X, ..., "b", ...)` as bytecode-loading.

### 12.2 Bytecode loading

```yaml
rules:
  - id: lua.bytecode-load
    languages: [lua]
    severity: ERROR
    message: |
      Loading Lua bytecode is documented in the reference manual
      as not consistency-checked: "Maliciously crafted binary
      chunks can crash the interpreter." Saelo's "Pwning Lua
      through 'load'" demonstrates the chain from bytecode load
      to arbitrary native code. Use load(s, name, "t", env) to
      reject bytecode.
    pattern-either:
      - pattern: load($X)             # default mode is "bt"
      - pattern: load($X, $NAME)
      - pattern: load($X, $NAME, "b")
      - pattern: load($X, $NAME, "b", ...)
      - pattern: load($X, $NAME, "bt")
      - pattern: load($X, $NAME, "bt", ...)
      - pattern: string.dump(...)
```

### 12.3 Debug library reachable from sandbox context

```yaml
rules:
  - id: lua.debug-library-reachable
    languages: [lua]
    severity: WARNING
    message: |
      The debug library is the canonical Lua sandbox-escape vector:
      debug.getupvalue/setupvalue walk closure captures;
      debug.getmetatable bypasses __metatable lockout;
      debug.sethook installs arbitrary hooks; debug.getlocal/setlocal
      reach the caller's stack. Defensive sandboxes must remove the
      entire debug table.
    pattern-either:
      - pattern: debug.getupvalue
      - pattern: debug.setupvalue
      - pattern: debug.getmetatable
      - pattern: debug.setmetatable
      - pattern: debug.sethook
      - pattern: debug.getlocal
      - pattern: debug.setlocal
      - pattern: debug.getinfo
      - pattern: debug.getregistry
      - pattern: debug.upvaluejoin
```

### 12.4 LuaJIT FFI

```yaml
rules:
  - id: lua.luajit-ffi-reachable
    languages: [lua]
    severity: ERROR
    message: |
      LuaJIT's FFI is a documented full-sandbox-escape primitive:
      ffi.C.system, ffi.cdef + ffi.cast, ffi.new + mprotect. There
      is no safe way to expose ffi to untrusted Lua code in
      LuaJIT. Remove the ffi require from the sandbox's scope or
      run untrusted Lua in a separate process.
    pattern-either:
      - pattern: require("ffi")
      - pattern: require 'ffi'
      - pattern: ffi.cdef
      - pattern: ffi.C
      - pattern: ffi.cast
      - pattern: ffi.load
```

### 12.5 `getmetatable` / `setmetatable` reachable from sandbox

```yaml
rules:
  - id: lua.metatable-reachable-from-sandbox
    languages: [lua]
    severity: WARNING
    message: |
      getmetatable and setmetatable are walkable identifiers; in
      a sandbox context they enable __index → string library →
      string.dump → bytecode chain. Defensive sandboxes must
      either remove these from the sandbox env or wrap the env
      construction with debug.setmetatable("", nil) to detach
      the shared string metatable.
    pattern-either:
      - pattern: getmetatable(...)
      - pattern: setmetatable(...)
      - pattern: rawget(...)
      - pattern: rawset(...)
```

### 12.6 LuaCheck and Lua Language Server

LuaCheck (`lunarmodules/luacheck`) is the canonical Lua
linter. The default ruleset reports:

- `setting non-standard global variable` (forgotten-`local`
  global writes)
- `accessing undefined variable` (typo'd global reads)
- `unused variable`
- `value assigned to a local variable is unused`
- `unreachable code`

For sandboxing-sensitive code, configure with:

```lua
-- .luacheckrc
std = "min"          -- minimal Lua standard library
globals = {}         -- allowlist additional globals here
ignore = {}          -- explicitly do NOT silence sandbox-relevant warnings
```

Lua Language Server (`LuaLS/lua-language-server`) provides
LSP-level diagnostics including type inference (with EmmyLua
annotations) and is the primary editor-integration option for
2024-2026 Lua development.

Cross-link: `semgrep_rule_authoring.md` for the
test-fixture-format conventions and OSS-corpus precision
measurement.

---

## 13. Defensive checklist and variant analysis

### 13.1 Ten-item defensive checklist for hosts embedding Lua

1. **Pick the right Lua dialect.** If untrusted Lua is in scope,
   use Luau or process-isolation. If only trusted Lua, PUC-Rio
   Lua 5.5 is the current stable release.
2. **Pass `mode = "t"` to `load`.** Reject bytecode at the parse
   step. Bytecode loading is documented-not-validated and the
   exploitation lineage is mature.
3. **Strip the dangerous-builtin set.** Minimum removal:
   `os`, `io`, `package`, `debug`, `ffi` (LuaJIT), `dofile`,
   `loadfile`, `require`. Then audit what remains.
4. **Detach the string metatable.** Call
   `debug.setmetatable("", nil)` *before* opening the sandbox
   to prevent `getmetatable("").__index` walk-back.
5. **Lock down metatables on every value exposed to the
   sandbox.** Set `__metatable` on every host-supplied table's
   metatable to prevent guest replacement.
6. **Install an instruction-count debug hook.** Limit guest
   computation via `debug.sethook(co, callback, "", N)` to
   bound CPU. The `kikito/lua-sandbox` reference implementation
   ships a 500,000-instruction default.
7. **Track and `coroutine.close` all guest-created coroutines.**
   Prevent memory and state leaks; Lua 5.4 makes this
   straightforward.
8. **Cap `string.rep`, `string.format` width, and table-size
   primitives.** Prevent allocation DoS.
9. **Run the sandbox in a separate OS process or container.**
   Process-level isolation is the only sandbox primitive that
   has held under sustained adversarial pressure. The LuaJIT FAQ's
   position (sandbox at the process level, not the VM level) applies in full.
10. **Pin Lua version and ship a maintained one.** Lua 5.1 is
    end-of-life from a security perspective; LuaJIT's mainline
    is a rolling release on the v2.1 branch with downstream forks
    (`openresty/luajit2`, `Tarantool/luajit`) carrying patches.
    Track upstream and apply patches.

### 13.2 Variant analysis: Luau, Pallene, Squirrel, Wren, Fennel

- **Luau** (Roblox, `luau.org`). Statically typed Lua dialect
  with sandbox-as-first-class-concern. Bytecode loading removed,
  per-script global tables, debug-library scoped down, FFI
  absent. The only mainstream Lua dialect that has held up
  under sustained adversarial pressure (luau.org: built to
  withstand the actively malicious code Roblox runs).
- **Pallene** (PUC-Rio LabLua,
  `https://github.com/pallene-lang/pallene`). Maidl /
  Gualandi / Mascarenhas / Ierusalimschy. Typed Lua companion
  language compiled to C, designed for performance-critical
  modules called from Lua. Not designed for sandboxing
  specifically; the type system reduces the audit surface but
  Pallene-compiled C modules can do anything the host C
  runtime allows.
- **Squirrel** (`http://squirrel-lang.org/`). Lua-inspired
  embeddable language, used in Portal 2 and other games. Same
  embedded-extension niche; same default-permissive footgun
  class. Squirrel-specific surface is narrower because the
  language is less widely deployed.
- **Wren** (`wren.io/`, Bob Nystrom). Lua-influenced
  embeddable language with class-based OO. Designed for
  small embeddings; the host application controls every
  binding explicitly. Wren is arguably closer to "embeddable
  by intent" than Lua in 2026; the trade-off is a smaller
  ecosystem.
- **Fennel** (`fennel-lang.org/`, Phil Hagelberg). Lisp-syntax
  compiler-to-Lua. Inherits Lua's entire footgun surface
  because the compilation target is Lua; treat Fennel as
  syntactically transformed Lua for audit purposes.

### 13.3 The "do not embed a Turing-complete language as a config format" doctrine

The recurring failure mode across the Lua-embedding corpus:

1. Host author chooses Lua "for configuration."
2. Users start writing scripts that exceed configuration's
   intent (loops, conditions, side effects).
3. Host author exposes more of the language surface to support
   the users' actual needs.
4. The configuration surface is now a scripting surface,
   running on user-controlled input, with host privileges.
5. Two years later: CVE.

The doctrine, restated:

- **Configuration files should be data formats, not programs.**
  TOML, YAML, JSON, .ini, .conf — these are unambiguously data.
  When a host needs conditional logic, expose conditional
  primitives in the data format (templates with explicit
  conditionals, schema-based validation), not a full language.
- **If you must embed a language, embed the smallest one that
  works.** Lua 5.4 stripped to `math` + `string` + the
  Roblox/Luau sandbox profile is a credible minimum. Anything
  more is a quarterly-CVE pipeline.
- **If you must run adversarial Lua, run it in a process.**
  Container, seccomp filter, separate user account, gvisor,
  Firecracker. The lua-users SandBoxes wiki has documented
  this for two decades.

(Cross-link: `code_review_expertise.md` — when reviewing a
host application that embeds Lua, the click-count severity
framework treats "any Lua surface reachable from untrusted
input" as zero-click; the audit should focus on whether the
host's binding choices align with the intended trust boundary,
not on the Lua code itself.)

---

## 14. References

### 14.1 PUC-Rio Lua reference

- Lua 5.4 Reference Manual — `https://www.lua.org/manual/5.4/manual.html`
- Lua 5.3 Reference Manual — `https://www.lua.org/manual/5.3/manual.html`
- Lua 5.2 Reference Manual — `https://www.lua.org/manual/5.2/manual.html`
- Lua 5.1 Reference Manual — `https://www.lua.org/manual/5.1/manual.html`
- Programming in Lua (Ierusalimschy) — `https://www.inf.puc-rio.br/~roberto/book/`
- The Evolution of Lua (HOPL III, 2007) — `https://www.lua.org/doc/hopl.pdf`
- Integers in Lua 5.3 (Ierusalimschy, Lua Workshop 2014) — `https://www.lua.org/wshop14/Ierusalimschy.pdf`
- Lua errata — `https://www.lua.org/bugs.html`

### 14.2 LuaJIT

- LuaJIT — `https://luajit.org/`
- LuaJIT FFI API — `https://luajit.org/ext_ffi_api.html`
- LuaJIT FFI Tutorial — `https://luajit.org/ext_ffi_tutorial.html`
- LuaJIT FAQ (Mike Pall's sandboxing position) — `https://luajit.org/faq.html`
- Malicious LuaJIT bytecode (corsix) — `https://www.corsix.org/content/malicious-luajit-bytecode`
- Exploiting Lua 5.1 on 32-bit Windows (corsix) — `https://gist.github.com/corsix/6575486`

### 14.3 Lua sandbox-escape research

- Pwning Lua through 'load' (saelo) — `https://saelo.github.io/posts/pwning-lua-through-load.html`
- lua-users wiki: Sand Boxes — `http://lua-users.org/wiki/SandBoxes`
- HackTricks Lua Sandbox Escape — `https://hacktricks.wiki/en/generic-methodologies-and-resources/lua/bypass-lua-sandboxes/index.html`
- Bytecode Corruption Attacks Are Real (DIMVA 2018) — `https://people.cs.kuleuven.be/~stijn.volckaert/papers/2018_DIMVA_Interpreters.pdf`
- Mitigating the Danger of Malicious Bytecode (Cawley, Lua Workshop 2011) — `https://www.lua.org/wshop11/Cawley.pdf`
- Redis EVAL Lua sandbox escape (benmmurphy, 2015) — `https://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/`
- Bytecode Breakdown: Factorio's Lua Security Flaws — `https://memorycorruption.net/posts/rce-lua-factorio/`

### 14.4 Embedding-specific

- Wireshark Lua Support — `https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html`
- Redis Lua API reference — `https://redis.io/docs/latest/develop/programmability/lua-api/`
- CVE-2022-0543 (Redis Lua, Debian/Ubuntu) — `https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce`
- Roblox Luau — `https://luau.org/`
- Roblox Luau SECURITY.md — `https://github.com/Roblox/luau/blob/master/SECURITY.md`
- Roblox Luau Sandbox — `https://luau.org/sandbox/`
- OpenResty lua-nginx-module — `https://github.com/openresty/lua-nginx-module`
- OpenResty Reference — `https://openresty-reference.readthedocs.io/en/latest/`
- CVE-2020-11724 (OpenResty ngx.location.capture smuggling) — `https://ultramangaia.github.io/blog/2020/OpenResty-Http-Request-Smuggling-Vulnerability-CVE-2020-11724.html`
- neovim Lua — `https://neovim.io/doc/user/lua.html`

### 14.5 Sandboxing libraries (reference implementations)

- kikito/lua-sandbox — `https://github.com/kikito/lua-sandbox`
- Mozilla lua_sandbox — `https://github.com/mozilla-services/lua_sandbox`
- APItools sandbox.lua — `https://github.com/APItools/sandbox.lua`

### 14.6 Typed Lua dialects and tooling

- Typed Lua paper (Maidl, Mascarenhas, Ierusalimschy, Dyla 2014) — `https://www.cristal.univ-lille.fr/dyla14/papers/dyla14-4-typed-lua-an-optional-type-system.pdf`
- Pallene: A statically typed companion language for Lua — `https://www.inf.puc-rio.br/~roberto/docs/pallene-sblp.pdf`
- LabLua publications — `http://www.lua.inf.puc-rio.br/publications.html`
- LuaCheck linter — `https://github.com/lunarmodules/luacheck`
- Lua Language Server — `https://github.com/LuaLS/lua-language-server`
- LPeg (Parsing Expression Grammars) — `http://www.inf.puc-rio.br/~roberto/lpeg/`

### 14.7 Environment and historical context

- Implementing setfenv in Lua 5.2+ (Leafo) — `https://leafo.net/guides/setfenv-in-lua52-and-above.html`
- lua-users wiki: Environments Tutorial — `http://lua-users.org/wiki/EnvironmentsTutorial`
- lua-users wiki: Detecting Undefined Variables — `http://lua-users.org/wiki/DetectingUndefinedVariables`
- lua-users wiki: Metamethods Tutorial — `http://lua-users.org/wiki/MetamethodsTutorial`

### 14.8 Cross-references within `~/ai/expertise/software/`

- `js_sandbox_escape_expertise.md` — parent doctrine on
  in-process language sandboxing
- `c_cpp_footguns_expertise.md` — LuaJIT FFI inherits C UB
- `code_review_expertise.md` — auditing host applications
  that embed Lua
- `semgrep_rule_authoring.md` — Lua-rule authoring conventions
- `redos_algorithmic_dos_expertise.md` — Lua patterns are not
  PCRE; LPeg has its own surface
- `deserialization_expertise.md` — Lua bytecode loading is the
  deserialization-class primitive
- `detection_engineering_expertise.md` — Sigma / EDR rules for
  Lua-embedding-host abuse
- `cicd_supply_chain_expertise.md` — neovim/editor-plugin
  supply chain
- `http_web_security.md` — OpenResty SSRF / smuggling surface
