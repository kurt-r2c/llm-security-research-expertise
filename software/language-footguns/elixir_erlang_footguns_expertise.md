# Elixir and Erlang/OTP Behavioral Footguns — BEAM Primitives That Are Unsafe by Default
## Synthesized from Joe Armstrong, Robert Virding, José Valim, Saša Jurić, Fred Hebert, Bryan Hunt, Stas Versilov, and the institutional EEF Security WG / Trail of Bits / NCC Group / Snyk Erlang-Elixir advisory corpus

> **Currency marker:** Last refreshed 2026-05-14. Closes out the
> language-specific behavioral-footgun catalog Class 1 P3 slot
> (Elixir + Erlang/OTP). Sibling docs at the start of every
> `*_footguns_expertise.md` in this directory.
>
> The BEAM family has a distinctive footgun shape: very few memory-
> safety issues (the runtime owns them) and very few classic
> injection issues at the call-site level (pattern matching
> displaces most string concatenation), but a large body of
> *runtime-shape* footguns where the cost of the wrong default is
> borne by the supervision tree, the cluster, or the BEAM scheduler
> rather than by a single function call. Load-bearing 2024-2026
> thread: CVE-2026-32688 (plug_cowboy atom-table exhaustion via
> HTTP/2 `:scheme` pseudo-header), CVE-2026-42793 (absinthe atom-
> exhaustion via attacker-controlled GraphQL SDL names), the
> ongoing Erlang distribution-cookie RCE surface (Insinuator
> writeups 2017-2024), the 2024 Paginator RCE pattern (Stöckli,
> Enumerable-protocol abuse), OTP 27 + Elixir 1.18 baseline.
>
> **Researchers:**
>
> - **Joe Armstrong** — Erlang co-creator at Ericsson, 1986-onwards;
>   2003 KTH PhD thesis "Making Reliable Distributed Systems in the
>   Presence of Software Errors" remains the canonical "let it crash"
>   + supervision-tree text. The decisions to make atoms permanent,
>   to make message-passing the only IPC primitive, and to make
>   supervision trees a first-class construct trace to his design
>   notebooks. Died April 2019.
>   `erlang.org/download/armstrong_thesis_2003.pdf`.
> - **Robert Virding** — Erlang co-creator alongside Armstrong at
>   Ericsson. Co-author *Concurrent Programming in Erlang* (1996).
>   Designed substantial portions of OTP's process model and the
>   pattern-matching compiler. Today active in BEAM-language design
>   via LFE (Lisp-Flavoured Erlang). `github.com/rvirding`.
> - **José Valim** — Elixir creator, 2011-present. Former Rails Core
>   Team (2010-2014; Ruby Hero 2010); Erlang User of the Year 2015.
>   Founded Plataformatec; now CAO at Dashbit (Tidewave, Livebook).
>   Designed Elixir's macro system, `mix`, the OTP-behavior wrappers,
>   `Stream`/`Enum`, `Task`/`Task.Supervisor`. Strong editorial line
>   on safe-by-default Elixir APIs.
>   `github.com/josevalim`, `dashbit.co/blog`.
> - **Saša Jurić** — Author of *Elixir in Action* (Manning, 3rd ed.
>   2024 on Elixir 1.15 + OTP 26). Canonical post-2014 reference for
>   OTP design patterns: GenServer-as-process-abstraction,
>   supervision-tree design, distribution patterns, ETS-as-shared-
>   cache hygiene, `:erlang.process_info`-based observability.
>   `theerlangelist.com`.
> - **Fred Hebert** — Author of *Learn You Some Erlang for Great
>   Good!* (No Starch 2013; free online) and *Erlang in Anger*
>   (2014), the canonical operational diagnostics text — mailbox
>   overflow, memory leak triage, `recon`, `pobox`. Also
>   *Property-Based Testing with PropEr, Erlang, and Elixir*
>   (Pragmatic, 2019). `ferd.ca`, `learnyousomeerlang.com`.
> - **Bryan Hunt** — Long-running Erlang/Elixir practitioner; former
>   Heroku, Riak Core / Basho. EEF Security Working Group
>   contributor. Voice on distribution-cookie hygiene, epmd
>   hardening, `relx`/`mix release` engineering, the "cluster trust
>   boundary" framing. `github.com/binarytemple`.
> - **Stas Versilov** — Founder of Paraxial.io (Elixir security
>   vendor; honeypot + vulnerability scanning + runtime protection).
>   Operates `paraxial.io/blog`, the post-2021 canonical single-
>   vendor source for Elixir security writeups: atom exhaustion,
>   Ecto `fragment` SQLi, `Code.eval_string` RCE, Phoenix Token
>   leakage, Sobelow false-positive hardening.
> - **NCC Group / Trail of Bits Erlang-Elixir corpus** —
>   institutional. NCC Group authored Sobelow (now community-
>   maintained at `github.com/sobelow/sobelow`), the Phoenix-focused
>   static analyzer encoding most of this doc's audit heuristics as
>   warnings. Trail of Bits runs Erlang/Elixir audits via the
>   `appsec.guide` Testing Handbook (BEAM section); audit reports on
>   RabbitMQ / CouchDB / Telegraf cover BEAM-side operational
>   hardening.
> - **Snyk Elixir CVE corpus + EEF CNA** — institutional. The Snyk
>   advisory database (`security.snyk.io`) catalogues per-package
>   Elixir/Erlang CVEs; the EEF CNA (`cna.erlef.org/cves`) is the
>   upstream guidance equivalent of the OWASP Cheat Sheet for BEAM
>   applications.
>
> **Cross-links to neighboring expertise docs:**
> `code_review_expertise.md` (audit recipes), `semgrep_rule_authoring.md`
> (detection), `race_conditions_concurrency_expertise.md` (BEAM
> scheduler, Agent races, Task.async_stream semantics),
> `shell_injection_expertise.md` (Port.open argv-vs-shell),
> `sql_dialect_footguns_expertise.md` (Ecto fragment surface),
> `cryptography_expertise.md` (`:rand` vs `:crypto`),
> `cicd_supply_chain_expertise.md` (Hex.pm + rebar3 + mix trust).
>
> **Currency caveat:** OTP 27 + Elixir 1.18 is the 2026 baseline.
> Elixir 1.18 introduced gradual set-theoretic types (Valim's
> research thread). Active-support window at `erlef.org/`.

---

## 1. The Behavioral-Footgun Framing

A *cross-language bug class* (SQL injection, deserialization, SSRF,
command injection) is defined by attacker control over a particular
semantic operation. A *behavioral footgun* is the inverse: a
language-internal primitive whose default behavior is unsafe
regardless of whether attacker control is established at the call
site. `String.to_atom(user_input)` is the canonical BEAM footgun: a
single-argument BIF whose default behavior under untrusted input is
"crash the entire BEAM by exhausting the global atom table." There
is no API-shape signal at the call site that this is unsafe; the
call looks like a perfectly normal "stringly typed" coercion. The
unsafe default makes the call site uniquely review-amenable.

The BEAM family is mixed. Memory safety is excellent — no C heap
exposed to Elixir/Erlang code, no equivalent of `unsafe`, no manual
lifetime management. The supervisor/process model surfaces a large
class of fault-tolerance primitives that are safe by default. But
the runtime primitives — the global atom table, the distribution
protocol, the NIF interface, the `Code.eval_string` surface, the
`:ets` shared-memory tables, the unbounded process mailbox — are
deeply unsafe by default. They were designed for a closed network of
mutually-trusting telecom switches, not for internet-facing services.
Moving the BEAM into web service contexts (Phoenix, RabbitMQ,
CouchDB, ejabberd) inherited these defaults; modernizing them has
been a slow 15-year project that is still ongoing.

### Erlang's BEAM VM, atom-based message passing, OTP supervision trees

BEAM (Bogdan/Björn's Erlang Abstract Machine, named for Bogumil
Hausman and Björn Gustavsson) is the canonical Erlang VM and the
only one supported in production for Elixir, Gleam, LFE, and other
BEAM-targeting languages. Its design assumptions are unusual:

1. **Processes are the unit of concurrency, isolation, and fault.**
   A BEAM process is not an OS process; it is a green-thread-like
   construct with its own heap (~2KB initial), its own mailbox, its
   own scheduler slice. A typical BEAM node runs 100K-10M processes.
2. **Atoms are the unit of identity.** Atoms (Elixir: `:foo`;
   Erlang: `foo`) are interned strings with O(1) equality. They name
   modules, functions, GenServer states, message tags. Stored in a
   global table that is NEVER garbage collected.
3. **Messages are the only IPC primitive.** `Process.send/2` (Elixir)
   or `Pid ! Msg` (Erlang) copies the message term to the receiver's
   mailbox. No shared memory at the language level; ETS is a
   documented escape valve.
4. **Code is hot-loadable.** `:code.load_file/1` swaps module
   versions at runtime. The VM retains at most two versions
   (current + old); a third load purges the old.

OTP (the standard library, despite the historical "Open Telecom
Platform" name) layers behaviors on these primitives: `gen_server`,
`gen_statem`, `supervisor`, `application`. The supervision tree
pattern is the structural defense against "let it crash."

### "Let it crash" philosophy vs operational reality

Joe Armstrong's "let it crash" (2003 thesis) is widely misunderstood.
The full claim is *"let it crash, then have something else clean up."*
The supervision tree is the cleanup mechanism. Discipline:

1. Pattern match on expected input; let the BEAM raise on the rest.
2. Wrap each unit of state in a process; state dies with the
   process, restarts re-init clean.
3. Wrap each process in a supervisor with a restart strategy:
   `:one_for_one`, `:one_for_all`, `:rest_for_one`, `DynamicSupervisor`.
4. `max_restarts` / `max_seconds` form an exponential-backoff guard;
   exceeding the budget bubbles up.

The operational reality is that **"let it crash" works for contained
faults and is dangerous for fault floods.** An attacker who can
repeatedly trigger a process crash inside a `DynamicSupervisor`
tree will hit the restart limit, take down the supervisor, and
cascade up. Default `max_restarts` of 3 in 5 seconds is easily
breached. The supervision tree's restart budget is itself a DoS
surface. Cross-link [[reference-code-review-expertise]] §"Click-count
severity" — a one-click crash that compromises the supervisor's
restart budget is one-click DoS against the entire application.

### Elixir is Erlang with syntax sugar — same VM, same footguns

Elixir compiles to BEAM bytecode and shares the runtime — same atom
table, same message-passing, same supervision behaviors, same ETS,
same distribution protocol, same NIF interface. Elixir adds: a Lisp-
shaped macro system, the `Stream` lazy enumerable, `Mix`, `ExUnit`,
`Plug`/`Phoenix`, `Ecto`, `Task`. Every Erlang/OTP footgun reaches
into Elixir verbatim; an Elixir audit and an Erlang audit have the
same target list because the unsafe primitives live in the runtime,
not the surface syntax.

Sections 2-11 catalog BEAM-runtime primitives whose default behavior
is unsafe in production threat models. Section 12 covers detection
(Semgrep + Sobelow + Credo + Dialyzer). Section 13 is the defensive
checklist plus variant analysis (Gleam, LFE, AtomVM). Section 14 is
the reference URL list. Selection criterion: *if you handed this
primitive to a developer with no prior BEAM security context, what
is the probability they would deploy it unsafely?* Anything above
~40% qualifies.

---

## 2. Atom-Table Exhaustion

### The primitive

Atoms are interned strings with O(1) equality. They are stored in
a process-global table that is shared across every process on the
BEAM node. The table is NEVER garbage collected. Default capacity
is 1,048,576 entries (`+t` runtime flag adjustable; raising it is a
mitigation but not a fix).

When the table reaches capacity, `system_limit` is raised, which
crashes the BEAM. There is no graceful degradation; the entire VM
goes down.

Atoms are created in three ways:

1. **Compile-time literals.** `:my_atom` in Elixir, `my_atom` in
   Erlang, when written in source code, becomes a permanent table
   entry at module load time. Bounded by the source code; safe.
2. **`String.to_existing_atom/1`** (Elixir) /
   `list_to_existing_atom/1` (Erlang). Converts a string to an atom
   ONLY IF the atom already exists in the table. Raises `ArgumentError`
   on miss. Safe under untrusted input — the table cannot grow.
3. **`String.to_atom/1`** (Elixir) / `list_to_atom/1`,
   `binary_to_atom/1` (Erlang). Converts unconditionally; creates a
   new table entry if needed. **Direct atom-exhaustion DoS primitive
   under untrusted input.**

```elixir
# UNSAFE — DoS against the entire BEAM node
def lookup_dynamic(name) do
  String.to_atom(name) |> GenServer.call(:get)
end

# SAFE — raises if `name` is not a known atom
def lookup_known(name) do
  String.to_existing_atom(name) |> GenServer.call(:get)
end
```

A single attacker request to a function calling `String.to_atom/1`
with `name` from query string can iterate atom values until the
table is exhausted. The attacker does not need to coordinate; a
single client sending requests with `name=a1, a2, a3, ...` produces
1M atoms in seconds.

### Real-world incidents

**CVE-2026-32688** — plug_cowboy atom exhaustion via HTTP/2
`:scheme` pseudo-header. Plug.Cowboy called `String.to_atom/1` on
the `:scheme` value from HTTP/2 frames; attacker-controlled
schemes each produced a new atom. Fix: allowlist `:scheme`.

**CVE-2026-42793** — absinthe (GraphQL) atom exhaustion via
attacker-controlled SDL names. Schema-introspection paths
constructed atoms from SDL field names without bounds.

**Pattern signature.** Any web framework converting a request
parameter to an atom for routing, dispatch, config lookup, or
JSON-key normalization is a candidate. Watch for `String.to_atom`,
`:erlang.binary_to_atom`, `List.to_atom`, `Module.concat/2` with
user input, and `Jason.decode!` with `keys: :atoms` (recursively
converts every JSON key to an atom — direct atom-exhaustion
primitive).

### Mitigations

Default to `String.to_existing_atom/1` at every call site taking
user input. `Jason.decode/2` uses `keys: :strings` (safe) or
`keys: :atoms!` (existing-atoms-only); never `keys: :atoms`. Raise
the `+t` flag (production: `+t 5000000` or higher). Monitor
`:erlang.system_info(:atom_count)` in production; alert at 80% of
`:atom_limit` (EEF Security WG canonical signal). Coerce strings
via a hand-rolled `Map` allowlist whose atoms pre-exist at module-
load time.

Sources: EEF Security WG "Preventing atom exhaustion"
(`security.erlef.org/secure_coding_and_deployment_hardening/atom_exhaustion.html`),
Paraxial.io "Elixir/Phoenix Security: Denial of Service Due to Atom
Exhaustion" (`paraxial.io/blog/atom-dos`), CVE-2026-32688 advisory
on the EEF CNA, CVE-2026-42793 advisory on the EEF CNA, Appunite
"Atom exhaustion" (`appunite.com/blog/atom-exhaustion`).

---

## 3. Mailbox Flooding and Selective Receive

### The primitive

Every BEAM process has a mailbox. The mailbox is **unbounded by
default** — the BEAM scheduler will accept incoming messages until
the receiving process's memory is exhausted, which on a BEAM node
manifests as the OS killing the BEAM emulator (OOM-killer; on Linux
this is `dmesg` "Killed process N (beam.smp)").

A `receive` clause does a **linear scan** of the mailbox starting
at the head, looking for the first message that matches a clause
pattern. Messages that don't match any clause stay in the mailbox.
This is "selective receive."

```erlang
receive
    {result, X} -> X
after
    5000 -> timeout
end.
```

Two failure modes interact:

1. **Producer faster than consumer.** If incoming message rate
   exceeds processing rate, the mailbox grows monotonically. Every
   `receive` scan now traverses a larger backlog. The process
   slows further. Eventually the BEAM OOM-kills.
2. **Selective receive on a never-matching pattern.** If the
   `receive` clauses do not match SOME of the incoming messages,
   the unmatched messages accumulate. Each subsequent `receive`
   re-scans them. Classic O(n²) blowup.

### "GenServer floods because `handle_info` is slower than arrival"

GenServer abstracts the receive loop; `handle_call`, `handle_cast`,
and `handle_info` are dispatched in arrival order. If `handle_info`
is slow (a synchronous I/O call, a slow ETS scan, a `:rpc.call/4`
to a remote node), and the inbound rate of `cast`/`info` exceeds
the dispatch rate, the GenServer mailbox grows.

The symptom: the GenServer's `handle_call` latency starts climbing
(because the mailbox scan to find the next `$gen_call` message is
now linear-time over the backlog). Eventually `handle_call` times
out at the *client* side with `:timeout`; the GenServer never
processed the call. The client retries; the mailbox grows further.

### Selective receive on a never-matching pattern

```erlang
%% BAD: if msg never arrives, every receive after this scans the
%% growing mailbox
loop() ->
    receive
        {ok, Result} -> handle(Result)
    end.
```

If something else is sending `{error, _}` messages to this process,
those messages pile up in the mailbox unread. `receive {ok, _}`
re-scans them every time. Classic Erlang antipattern; documented in
Fred Hebert's *Erlang in Anger* §"Memory Leaks."

### Mitigations

Bound producer rates via `GenStage`, `Flow`, `Broadway` (structured
back-pressure). Use `pobox` (Fred Hebert) as an external buffer
process with bounded capacity + drop policy. Monitor
`:erlang.process_info(pid, :message_queue_len)`; alert at 1000+;
combine with `:recon.proc_count(message_queue_len, 10)` for worst
offenders. `process_flag(:message_queue_data, :off_heap)` partially
mitigates GC cost but does NOT bound size. Use match-anything
receive clauses with internal dispatch to avoid never-match
accumulation. Cross-link
[[reference-race-conditions-concurrency]] §"Back-pressure."

Sources: Erlang Solutions "Receiving messages in Elixir, or a few
things you need to know in order to avoid performance issues"
(`erlang-solutions.com/blog/receiving-messages-in-elixir-...`),
Fred Hebert *Erlang in Anger* (`erlang-in-anger.com`), pobox
documentation (`github.com/ferd/pobox`), `:erlang.process_info/2`
documentation on `erlang.org`.

---

## 4. GenServer State Mutation Surprises

### The primitive

A GenServer is a process that holds state and serves callbacks.
The state is per-process; messages enter via `handle_call`/
`handle_cast`/`handle_info`; each callback returns a tuple whose
last element is the new state.

```elixir
def handle_call({:get, key}, _from, state) do
  value = Map.get(state.cache, key)
  {:reply, value, state}  # <-- state threaded through
end

def handle_call({:put, key, val}, _from, state) do
  new_cache = Map.put(state.cache, key, val)
  {:reply, :ok, %{state | cache: new_cache}}  # <-- state updated
end
```

The pattern is mechanical: every callback receives `state`, returns
the new state. Forgetting to update the returned state means the
mutation is silently dropped — the callback returns the OLD state,
the GenServer continues with the OLD state, and subsequent calls
see the OLD state.

### "I forgot to thread state through" silent state-loss bug

```elixir
# WRONG — new_cache computed but never returned
def handle_call({:put, key, val}, _from, state) do
  new_cache = Map.put(state.cache, key, val)
  {:reply, :ok, state}  # <-- BUG: returns old state
end
```

Compiles. Dialyzer often does not catch it (state type unchanged
from one callback to the next). ExUnit catches it only if a test
specifically checks the post-mutation state. **Any "build a new
value then discard it" pattern in functional code is silently
broken.** Credo's `Credo.Check.Warning.UnusedVariable*` family is
the first line of defense.

### `Task.start` vs `Task.async` vs `Task.async_stream`

| Primitive | Link | Monitor | Supervised | Failure mode |
|---|---|---|---|---|
| `Task.start/1` | No | No | No | Silent crash; caller never notified |
| `Task.start_link/1` | Yes | No | No | Crash propagates; caller dies |
| `Task.async/1` | Yes | Yes | No | Propagates + `Task.await` returns error |
| `Task.Supervisor.start_child/2` | Opt | Opt | YES | Supervisor restart policy applies |
| `Task.async_stream/3` | Yes | Yes | YES | Bounded concurrency + restart |

`Task.start/1` is the "fire and forget" footgun: crashes vanish
silently. `Task.async/1` requires a matching `Task.await/2`; failing
to await leaves a linked process + dangling monitor (memory-leak
shape). `Task.async_stream/3` is the modern structured-concurrency
default. Cross-link
[[reference-race-conditions-concurrency]] §"Structured concurrency."

### `Agent.update` read-modify-write races

```elixir
# WRONG — race window between get and update (two messages)
value = Agent.get(agent, & &1)
Agent.update(agent, fn _ -> value + 1 end)

# RIGHT — single atomic message
Agent.get_and_update(agent, fn v -> {v + 1, v + 1} end)
```

**Any process-state operation that requires two messages instead
of one is racy.** ETS has the same shape — `:ets.lookup/2` then
`:ets.insert/2` is racy; `:ets.update_counter/3` is atomic.
Cross-link §5.

### `Registry` and process discovery

`Registry` collisions in unique-key mode are a real production
hazard during hot-code-reload (new module starts before old has
fully exited). Mitigate with `:via` tuples and explicit timeout in
`start_link`.

Sources: Elixir `GenServer` documentation
(`hexdocs.pm/elixir/GenServer.html`), Saša Jurić *Elixir in
Action* 3rd ed. ch. 6-7, Elixir `Task` and `Agent` documentation,
Erlang Solutions blog on GenServer patterns.

---

## 5. ETS Tables and Shared State

### The primitive

ETS (Erlang Term Storage) is the BEAM's shared-memory escape valve.
A process creates a table; other processes can read or write it
depending on the access mode.

```elixir
table = :ets.new(:my_table, [:set, :public, :named_table, read_concurrency: true])
:ets.insert(table, {:key, "value"})
:ets.lookup(table, :key)  #=> [{:key, "value"}]
```

Key knobs:

| Option | Default | Meaning |
|---|---|---|
| `:set` | Yes | One value per key (last-write-wins) |
| `:ordered_set` | No | Same as `:set` but ordered by key; allows range scans |
| `:bag` | No | Multiple distinct values per key |
| `:duplicate_bag` | No | Multiple values per key, duplicates allowed |
| `:public` | No | Any process can read AND write |
| `:protected` | Yes (default) | Owner writes; any process reads |
| `:private` | No | Owner reads AND writes; no other process |
| `:named_table` | No | Atom name routable via `:ets.lookup/2` directly |
| `read_concurrency: true` | No | Optimize for read-heavy workloads |
| `write_concurrency: true` | No | Optimize for write-heavy workloads |

### The `:public` footgun

`:public` is the highest-risk option. Any process on the node can
write to the table without coordination. Race conditions on
`:public` tables are a classic source of silent data loss.
`:ets.update_counter/3` is atomic; `:ets.lookup/2` + `:ets.insert/2`
is not. Audit pattern: any `:public` table should ONLY use atomic
update primitives (`:ets.update_counter`, `:ets.update_element`,
`:ets.insert_new`).

### Table type semantics

Wrong table type produces silent semantic bugs. Common error:
developer wanted "list of values under each key" but chose `:set`;
every insert overwrites the previous value. `:ordered_set` is the
only type supporting range scans (`:ets.select/2` with comparison
guards); other types are hash tables.

### Lifecycle: owner crashes, table dies

ETS tables are owned by the process that created them. **When the
owner dies, the table is destroyed.** Mitigations: use `:heir`
option for ownership transfer on death (heir is typically a
long-lived supervisor); create ETS tables in supervisors not in
short-lived GenServers; use `:ets.give_away/3` for programmatic
handoff during hot-code-reload / blue-green deploys.

### DETS — disk-backed ETS

DETS writes are buffered, flushed on close or `:dets.sync/1`. A
crash during write loses unflushed data. 2GB size limit (legacy
32-bit file pointer). DETS is not a database; for real persistence
use Mnesia or an external DBMS via Ecto.

### Audit recipe

Every `:ets.new/2`: document access mode. Every `:public` table:
verify all writers use atomic primitives. Every table: confirm
owner is supervisor or long-lived process, or `:heir` is set.
Confirm type matches semantic intent.

Sources: Erlang `ets` documentation
(`erlang.org/doc/apps/stdlib/ets.html`), Elixir School "Erlang
Term Storage (ETS)"
(`elixirschool.com/en/lessons/storage/ets`), Fred Hebert *Learn
You Some Erlang* "Bears, ETS, Beets"
(`learnyousomeerlang.com/ets`).

---

## 6. Pattern Matching and Binary Syntax

### The primitive

Erlang/Elixir's bit syntax is the canonical primitive for parsing
binary protocols. Patterns describe sequences of bit-width
segments; matching extracts values; constructing assembles them.

```erlang
%% Parse a length-prefixed packet
<<Size:16/big-unsigned, Payload:Size/binary, Rest/binary>> = Data.
```

```elixir
<<size::16, payload::binary-size(size), rest::binary>> = data
```

Defaults to watch for:

| Type | Default size | Endianness | Sign |
|---|---|---|---|
| `integer` | 8 bits | big | unsigned |
| `float` | 64 bits | big | (not applicable) |
| `binary` | "all remaining bytes" | (not applicable) | (not applicable) |
| `bitstring` | "all remaining bits" | (not applicable) | (not applicable) |

The "all remaining bytes" default for `binary` is load-bearing — and
unsafe under untrusted protocol input.

### Unspecified bit-size matches greedy

```elixir
# WRONG — `payload` takes the rest; `size` is unused
<<size::16, payload::binary>> = data

# CORRECT — `payload` has the size encoded in the protocol
<<size::16, payload::binary-size(size), rest::binary>> = data
```

In adversarial parsing contexts (HTTP/2 frame parsing, custom
protocol decoders), this is a parser-differential primitive: if
the protocol intends `Y` to be exactly K bytes but the developer
wrote `Y::binary` (greedy), downstream consumers receive arbitrary
trailing bytes as payload.

### `bit_size` vs `byte_size` confusion

`bit_size(B)` returns total bits; `byte_size(B)` returns
`ceil(bit_size(B) / 8)`. For bitstrings (binaries that are not a
multiple of 8 bits), `byte_size`-based buffer slices lose up to
7 bits silently.

### Size-prefix validation

Without explicit validation, an attacker sends `size=65535` with a
100-byte payload; the match fails with `MatchError`. In a Plug
pipeline this becomes a 500 + log-volume DoS amplification.
Mitigation: validate `size` against `byte_size(rest)` in a guard
BEFORE the binary-size match:

```elixir
case data do
  <<size::16, rest::binary>> when byte_size(rest) >= size ->
    <<payload::binary-size(size), tail::binary>> = rest
    {:ok, payload, tail}
  _ ->
    {:error, :short_packet}
end
```

### "I copied a protocol parser without bounds-checking"

Canonical signature: developer copies a binary pattern from an RFC
or another library; default integer width (8 bits) is wrong for the
protocol field; binary `size` is taken from the wire without
validation; trailing-bytes default is greedy. Result: parser-
differential vulnerabilities, HTTP request smuggling, frame-length
confusion. Audit: `grep -rn "<<" lib/ | grep "::"` — for each
match, verify every integer field has explicit width, every
attacker-controlled-size field has a bounds check, and the match
arm has structured error handling rather than raising.

Sources: Erlang "Constructing and Matching Binaries"
(`erlang.org/doc/system/binaryhandling.html`), Erlang "Bit Syntax"
(`erlang.org/doc/system/bit_syntax.html`), "Optimizing Erlang
Binary Matching" (`rhye.org/post/erlang-binary-matching-performance/`).

---

## 7. Code Loading and Hot-Code-Reload

### The primitive

The BEAM allows runtime module replacement. `:code.load_file(:Module)`
loads a `.beam` file into the VM and atomically swaps it in. The
old version is kept; the BEAM retains both "current" and "old"
versions per module. A third load purges the old version (and any
process executing in old-version code is killed).

This is the basis of Erlang's celebrated uptime — telephony
switches with continuous operation across software releases. It is
also a substantial attack surface.

### `Code.eval_string(user_string)` — direct RCE

```elixir
# DIRECT RCE PRIMITIVE — never call with untrusted input
Code.eval_string("System.cmd(\"rm\", [\"-rf\", \"/\"])")
```

`Code.eval_string/3` parses Elixir source code and evaluates it in
the current process. The evaluated code has full BEAM privileges:
it can call any function in any loaded module, spawn processes,
open ports, read files, exec subprocesses. **Any path from
untrusted input to `Code.eval_string/3` is a direct RCE.**

The Elixir module documentation explicitly says: "Code.eval_string
can execute any Elixir code with the same privileges as the Erlang
VM, which means such code could compromise the machine (for
example by executing system commands), so it should never be used
with untrusted input such as strings coming from the network."

### Real-world incidents

**Alchemist-Server (2017).** `alchemist-server` Elixir tooling
exposed `Code.eval_string/1` over a local TCP socket; any process
on the developer's machine could exec arbitrary Elixir (Appcanary
writeup).

**Paginator library RCE (Stöckli, 2020).** Elixir's `Enumerable`
protocol accepts arity-2 functions in specific cases. Malicious
functions passed to `Enum.zip/1` executed; Paginator deserialized
request parameters into terms including function values.
Cross-link [[reference-deserialization-expertise]].

### `Code.eval_quoted(ast)` and `Code.require_file/2`

Same risk shape as `Code.eval_string/3` with AST or file-path
inputs. Macros that build ASTs from user input then evaluate them
are direct RCE. If an attacker can write `/tmp/x.exs` and trigger
`Code.require_file("x.exs", "/tmp")`, contents execute.

### Hot-code-reload + state migration

`:sys.change_code/4` invokes `code_change/3` on upgrade. If
`code_change/3` is missing or wrong, the state shape mismatch
crashes the GenServer; supervised processes restart with `init/1`
clean state, losing accumulated runtime state. An attacker who can
trigger a code change can force-restart processes by introducing a
state-shape mismatch. The BEAM retains current+old versions; a
third load purges old version and kills any process executing in
it.

Sources: Elixir `Code` module documentation
(`hexdocs.pm/elixir/Code.html`), Paraxial.io "Elixir/Phoenix
Security: Remote Code Execution and Serialisation"
(`paraxial.io/blog/elixir-rce`), Appcanary "Hacking your Elixir
Editor" (`blog.appcanary.com/2017/hacking-your-elixir-editor.html`),
"OS command and code execution in Erlang and Elixir applications"
(`vuln.be/post/os-command-and-code-execution-in-erlang-and-elixir/`).

---

## 8. Distribution and Clustering

### The primitive

Erlang distribution is the protocol by which multiple BEAM nodes
form a cluster. Two BEAM nodes that know each other's
authentication cookie can establish a TCP connection and exchange
arbitrary Erlang terms — including remote function call requests.

```erlang
%% From node1 to node2:
rpc:call('node2@host', os, cmd, ["rm -rf /"]).
```

This is "any node with the cookie can run any function on any
other node." It is RCE by design — within a trusted cluster, this
is the feature. Outside one, it is a critical vulnerability.

### Cookie-based authentication is symmetric, shared, easily-discovered

The cookie is a symmetric secret. `~/.erlang.cookie` is auto-
generated on first BEAM boot as a 20-character alphanumeric string
(`[A-Z]+`), file mode 0400 on Unix. Failure modes: any process
running as the same user can read it; it can be logged via
`-setcookie` command-line args visible to `ps aux`; auto-generation
entropy is the BEAM's default RNG (NOT cryptographically secure);
Windows installs often have weaker permissions. Insinuator 2017
documents crackable cookies in production.

### Cluster trust model

Once the cookie is shared, any node can call any function on any
other node. **No per-function authorization** in the distribution
protocol. `:rpc.call/4` (Erlang), `:erpc.call/4` (Erlang 23+), and
`Node.spawn/4` (Elixir) all give arbitrary code execution on the
remote node.

### Real CVEs and exploit kits

**Erlang Port Mapper Daemon (epmd) Cookie RCE** —
exploit-db.com/exploits/46024 + 49418, Metasploit module
`exploit/multi/misc/erlang_cookie_rce`. epmd listens on TCP/4369 by
default. epmd does not authenticate — it tells callers the port for
a named BEAM node; the caller then handshakes using the cookie.
The Insinuator 2017 writeup includes a brute-forcer; the protocol
does NOT rate-limit handshake attempts.

### The "epmd on public interface" footgun

Default `epmd` binds to all interfaces (0.0.0.0). Cloud deployments
routinely expose BEAM nodes (Phoenix apps, RabbitMQ, CouchDB,
ejabberd) with epmd unintentionally Internet-reachable. Combined
with a guessable/weak cookie, this is direct RCE.

Mitigations: bind epmd to localhost (`ERL_EPMD_ADDRESS=127.0.0.1`);
use a long random cookie from `/dev/urandom` (NOT `:rand.uniform/1`);
configure TLS distribution (`-proto_dist inet_tls` with
`server_certfile`/`server_keyfile`/`server_cacertfile` + `verify
verify_peer` + `fail_if_no_peer_cert true`) to replace the cookie
with mutual TLS; network-segment the cluster into a private VPC.
Monitor `:net_kernel.connect_node/1` calls; unexpected
`nodedown`/`nodeup` are IOCs.

Cross-link [[reference-cryptography-expertise]] §"TLS with mutual
authentication."

Sources: Insinuator "Erlang distribution RCE and a cookie
bruteforcer" (`insinuator.net/2017/10/erlang-distribution-rce-and-a-cookie-bruteforcer/`),
exploit-db.com/exploits/49418 ("Erlang Cookie - Remote Code
Execution"), Rapid7 module
`exploit/multi/misc/erlang_cookie_rce`, gteissier/erl-matter
(`github.com/gteissier/erl-matter`), Security Boulevard "Erlang
Authenticated Remote Code Execution" (2018-09).

---

## 9. External Port and NIF Safety

### `Port.open/2` and shell injection

```elixir
# UNSAFE — shell injection
Port.open({:spawn, "ls #{user_input}"}, [])

# SAFE — no shell, argv directly
Port.open({:spawn_executable, "/bin/ls"}, [args: [user_input]])
```

The `:spawn` form invokes a shell (`sh -c CMD` on Unix, `cmd.exe
/c` on Windows). Shell metacharacters in `user_input` —
`;`, `|`, `` ` ``, `$()`, `&`, `>`, `<`, `\n` — are interpreted
by the shell. This is direct command injection.

The `:spawn_executable` form takes an explicit executable path and
an argument list. Arguments are passed via `execve(2)` directly;
no shell, no metacharacter interpretation. This is the safe form.

Even `:spawn_executable` has a subtlety: on Windows, batch files
(`.bat`, `.cmd`) and certain `.exe` files implicitly invoke
`cmd.exe`'s parser. Arguments that contain quotes, ampersands, or
caret characters can still escape into command-injection territory.
The EEF Security WG documentation on `external_executables` is
the canonical reference; key recommendation: "if running on
Windows and executing batch files or .com applications, you must
not pass untrusted input as arguments."

Cross-link [[reference-shell-injection]] §"argv vs string-shell"
for the cross-language taxonomy.

### `System.cmd/3` is safer than `Port.open/2` by default

```elixir
# SAFE — argv form, no shell
System.cmd("ls", [user_input])
```

`System.cmd/3` (Elixir 1.x) takes the executable as the first
argument and argv as the second. It is the recommended API for
"run a subprocess" use cases. Equivalent to
`Port.open({:spawn_executable, ...}, args: ...)` plus collecting
stdout/stderr.

### NIFs (Native Implemented Functions)

NIFs are C functions registered with the BEAM that implement Erlang
functions in native code (crypto, regex, JSON parsing, image
processing). **A crash in a NIF brings the entire BEAM down.** From
the Erlang NIF documentation: "An erroneously implemented native
function can cause a VM internal state inconsistency, which can
cause a crash of the VM, or miscellaneous misbehaviors of the VM
at any point after the call to the native function."

Safety hazards: (1) memory safety — NIF is C, so the C unsafe set
applies (cross-link [[reference-c-cpp-footguns-expertise]]);
(2) resource accounting — NIFs allocating outside the BEAM's
accounting bypass OOM prevention; (3) scheduler blocking — NIFs
>1ms block their scheduler thread; N long-running NIFs deadlock
the BEAM's N schedulers.

### Dirty NIFs vs regular NIFs

Erlang 17.3+ introduced dirty schedulers: `ERL_NIF_DIRTY_JOB_CPU_BOUND`
(`+SDcpu` pool) for CPU-bound work, `ERL_NIF_DIRTY_JOB_IO_BOUND`
(`+SDio` pool) for I/O. **Rule: always use dirty schedulers for
NIFs that take >1ms.** Audit pattern: every NIF should declare its
scheduling expectations or document why it doesn't.

### Rustler — Rust NIFs

`rustler` is the Rust-NIF binding crate. Rust's borrow checker
catches C-style memory-safety hazards at compile time; modern
Elixir NIFs are typically Rust + Rustler, not C. Remaining hazard:
Rust panics in a NIF call `std::process::abort` on the BEAM
emulator. Rustler 0.30+ supports panic-catching via
`#[rustler::nif(panic = "catch")]`; without opt-in, a panic still
aborts the BEAM.

Sources: Erlang "NIFs" (`erlang.org/doc/system/nif.html`),
Erlang "Debugging NIFs and Port Drivers"
(`erlang.org/doc/system/debugging.html`), Rustler crate docs
(`docs.rs/rustler`), Andrea Leopardi "Using C from Elixir with
NIFs" (`andrealeopardi.com/posts/using-c-from-elixir-with-nifs/`),
EEF Security WG "Spawning external executables"
(`erlef.github.io/security-wg/secure_coding_and_deployment_hardening/external_executables.html`).

---

## 10. Phoenix-Specific Footguns

### Phoenix.LiveView server-side state

LiveView holds connection state on the server: the LV process
state, the assigns map, the rendered DOM diff base. State persists
across reconnects via a session token. Hazards: state carries
authorization context (if `mount/3` stored `current_user`, every
subsequent `handle_event/3` runs as that user); `live_session`
boundary IS the authorization boundary (in-session navigations do
NOT remount); `handle_params/3` must re-authorize when URL
parameters change (`live_patch` rewrites them); LV processes are
long-lived so per-event state accumulation is DoS-able.

### `Plug.Conn.put_session/3` — session storage

Default `Plug.Session.COOKIE` signs+optionally-encrypts the session
into a ~4KB cookie via `:secret_key_base`. Hazards:
`:secret_key_base` leakage forges every cookie; load from
`config/runtime.exs` (env var or secrets manager) NOT
`config/prod.exs` (compiled into release artifact). Cookie size
limit means session truncation. `Plug.Session.ETS`/`MNESIA` are
server-side alternatives; both grow monotonically without explicit
expired-session purge.

### `Plug.CSRFProtection` defaults

Phoenix's `:browser` pipeline includes CSRF protection by default;
`:api` pipelines bypass it (JSON APIs use Bearer tokens). Audit
hazard: mixed-content endpoints that accept both JSON and form
bodies — attacker submits a form with `Content-Type:
application/json` to bypass browser same-origin protections; the
server processes it as JSON without CSRF.

### `Phoenix.Token` signing key shared across servers

`Phoenix.Token` derives signing keys from `:secret_key_base`.
Tokens signed by one server are valid on every server sharing the
secret (intended for load-balanced deployments). **Rotating
`:secret_key_base` invalidates every token simultaneously** —
logged-in sessions, in-flight password-reset links, pending
email-confirmation tokens. Rotation requires multi-secret
verification or forced re-login. Use `:max_age` to bound token
lifetime independent of key rotation.

### `Ecto.Query` raw fragments + interpolation

```elixir
# UNSAFE — direct SQL injection via Repo.query!
Ecto.Adapters.SQL.query!(MyRepo, "SELECT * FROM users WHERE id = #{user_id}")

# UNSAFE — unsafe_fragment with user input
from u in User, where: unsafe_fragment("name = '#{user_name}'")

# SAFE — fragment with parameters
from u in User, where: fragment("name = ?", ^user_name)
```

Ecto's `fragment/1` macro accepts SQL with `?` placeholders that
bind to following arguments via the `^` interpolation operator. By
design, `^value` becomes a parameterized bind, not a string
substitution. **The Elixir parser refuses to compile `^value` as
the first argument to `fragment/1`** — this is a load-bearing
compile-time guardrail.

The bypasses:

1. **`unsafe_fragment/1`** — explicit opt-out. Allows interpolated
   binaries. The name is intentional warning. Any
   `unsafe_fragment` in a codebase is an audit finding requiring
   justification.
2. **`Ecto.Adapters.SQL.query!/3`** — direct SQL execution; takes
   a raw SQL string and a parameter list. Interpolating a user
   value into the SQL string is direct SQLi. Use the parameter
   list (second argument), never string interpolation.
3. **`Ecto.Query.from` with `where: ^"..."`** — dynamic where
   clauses can be assembled with `Ecto.Query.dynamic/2`, which
   has its own injection-safe interpolation. Hand-rolled string
   assembly defeats Ecto's protection.

Cross-link [[reference-sql-dialect-footguns]] §"PostgreSQL"
(the typical Ecto-side dialect) and §"MySQL" for the
dialect-specific quoting hazards that survive Ecto's
parameterization.

### Channel subscription authorization

Phoenix Channels (the WebSocket layer) authorize at `join/3`. The
return shape `{:ok, socket}` accepts the join; `{:error, reason}`
rejects. **Post-join messages are NOT re-authorized by the
framework.** If `join/3` checked that the user has read access to
topic `room:42`, but doesn't re-check on each
`handle_in("send_message", ...)`, an authorized-to-read user can
send messages.

Audit pattern: every `handle_in/3` clause that modifies state
should check the user's authorization for that operation,
independent of the join check. The room-read vs room-write
distinction is exactly the CWE-862 (missing authorization) /
CWE-863 (incorrect authorization) boundary documented in
[[reference-distributed-authz-expertise]].

Sources: Phoenix LiveView documentation
(`hexdocs.pm/phoenix_live_view`), Plug.CSRFProtection
documentation (`hexdocs.pm/plug/Plug.CSRFProtection.html`),
Phoenix.Token documentation (`hexdocs.pm/phoenix/Phoenix.Token.html`),
Ecto.Query.API documentation
(`hexdocs.pm/ecto/Ecto.Query.API.html`), Paraxial.io "Detecting
SQL Injection in Phoenix with Sobelow"
(`paraxial.io/blog/sql-injection`).

---

## 11. BEAM Cryptography

### The primitive

The `:crypto` and `:public_key` Erlang modules wrap OpenSSL via
the `crypto` NIF. They provide hashing, HMAC, symmetric and
asymmetric encryption, key derivation, certificate parsing, TLS
primitives.

Cross-link [[reference-cryptography-expertise]] for the
cross-language cryptographic-primitive doctrine. This section
covers BEAM-specific hazards.

### `:crypto.strong_rand_bytes/1` (cryptographic) vs `:rand.uniform/1` (NOT cryptographic)

```elixir
# CRYPTOGRAPHIC — backed by /dev/urandom or BCryptGenRandom
session_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64()

# NOT CRYPTOGRAPHIC — exposed PRNG state, predictable
weak_token = :rand.uniform(2**128) |> Integer.to_string()
```

`:rand.uniform/1` (and the older `random:uniform/1`) is a fast PRNG
for simulation use. The state is per-process and accessible via
`:rand.export_seed/0`; an attacker who observes a few outputs can
reconstruct the seed and predict future outputs. Using
`:rand.uniform/1` for session tokens, password-reset codes, CSRF
tokens, or any security-relevant random value is a critical bug.

The Erlang `crypto:strong_rand_bytes/1` BIF wraps `RAND_bytes`
from OpenSSL, which reads from `/dev/urandom` on Linux/macOS and
`BCryptGenRandom` on Windows. It is cryptographically secure.

Audit pattern: `grep -rn "rand:uniform\|:rand\." lib/ | grep -v
"test"`. Every match in non-test code is a candidate for review;
ask "is this output ever attacker-observable, and does its
predictability affect security?"

### `:crypto.hash/2` and `:crypto.mac/4`

MD5 and SHA-1 still compile cleanly via `:crypto.hash(:md5, ...)`;
use only for non-cryptographic checksums. **Password hashing via
`:crypto.hash` is wrong** — use Argon2/Bcrypt/Pbkdf2 Elixir
libraries; `:crypto.hash` is not a KDF (no iteration, no salt,
GPU-trivial). HMAC requires keys at the hash's block size; HMAC-
SHA-256 with a 16-byte key is reduced-security.

### `:public_key` and `:ssl` cert validation

BEAM-specific hazard: `:ssl.connect/3` WITHOUT
`verify: :verify_peer` does NOT validate the server certificate
(default `:verify_none` accepts any cert from any hostname).
Recurring audit finding in custom HTTPS clients on top of `:ssl`.
Use `:hackney`, `:mint`, `:finch`, or `:tesla` — all default to
`:verify_peer` with proper CA bundles. Cross-link §8 for TLS
distribution and [[reference-cryptography-expertise]] for
cert-pinning doctrine.

Sources: Erlang `:crypto` documentation
(`erlang.org/doc/apps/crypto/crypto.html`), Erlang `:public_key`
documentation, Erlang `:ssl` documentation,
[[reference-cryptography-expertise]] §"PRNG selection," §"Password
hashing," §"Certificate validation."

---

## 12. Detection Patterns

### Semgrep patterns

Elixir-specific Semgrep grammar coverage is partial as of 2026;
many Elixir audits use generic mode with regex anchoring. Sink
patterns to encode: `String.to_atom($USER)` (atom exhaustion),
`Code.eval_string($X)` (RCE), `Port.open({:spawn, $CMD}, $OPTS)`
(shell injection), `Ecto.Adapters.SQL.query!($REPO, $SQL)` and
`$REPO.query!($SQL)` (raw SQL), `:rand.uniform($N)` in security
context (predictable PRNG), `:erlang.binary_to_term($X)` on
untrusted bytes (term-constructor RCE), `Jason.decode!($X, keys:
:atoms)` (atom exhaustion via JSON). Cross-link
[[reference-semgrep-rule-authoring]] §"Generic-mode patterns."

### Sobelow — Phoenix-focused static analyzer

Sobelow is the Phoenix ecosystem's de facto security scanner.
Originally NCC Group; now community-maintained. Run as `mix
sobelow`. Key modules: `Config.CSRF`, `Config.Headers`,
`Config.Secrets`, `Config.HTTPS`, `XSS.Raw`/`XSS.HTML`/`XSS.SendFile`,
`SQL.Query`/`SQL.Stream`, `Traversal.FileModule`/`Traversal.SendFile`,
`Misc.BinToTerm` (the `:erlang.binary_to_term/1` on untrusted bytes
sink — direct RCE), `Misc.FilePath`, `Vuln.HeaderInject`.
Confidence levels HIGH/MEDIUM/LOW; `--threshold` flag filters in CI.
False-positive management via `# sobelow_skip ["XSS.Raw"]` comment
before the function.

### Credo — code quality and idiom

General-purpose Elixir style checker. Footgun-adjacent checks:
`Credo.Check.Warning.UnusedVariable*` (catches the GenServer
state-not-threaded bug from §4), `Credo.Check.Warning.IoInspect`
(`IO.inspect` left in production leaks data to logs).

### Dialyzer — type-spec verification

Success-typing static checker. Reports what is definitely wrong,
not what might be wrong. Catches type-mismatch crashes, dead
clauses, contract violations. **Does not track taint**; cannot
catch `String.to_atom(user_input)` as a security issue. Elixir
1.18's new gradual set-theoretic types (Valim's research thread)
coexists with Dialyzer; security-relevant payoff is not yet
mature.

Cross-link [[reference-semgrep-rule-authoring]] §"Per-language
analyzer stack" — canonical Elixir/Phoenix stack is Sobelow +
Credo + Dialyzer + Semgrep.

Sources: Sobelow documentation
(`github.com/sobelow/sobelow`), Paraxial.io "Elixir Security: A
Guide to Fixing Sobelow Findings" (`paraxial.io/blog/sobelow-guide`),
Credo documentation (`github.com/rrrene/credo`), Dialyzer
documentation (`erlang.org/doc/apps/dialyzer/dialyzer.html`).

---

## 13. Defensive Checklist + Variant Analysis

### 12-item defensive checklist

1. **Atom hygiene.** No `String.to_atom`/`list_to_atom`/`binary_to_atom`
   on untrusted input. JSON decoders use `keys: :strings`/`atoms!`.
   `+t` raised; `:atom_count` monitored.
2. **Mailbox discipline.** Monitor mailbox lengths; alert at
   1000+. GenStage/Flow/Broadway for back-pressure. No
   never-matching selective receive.
3. **GenServer state threading.** All callbacks return updated
   state. `Agent.get_and_update/2` instead of `get + update`.
4. **ETS access mode.** No `:public` without atomic primitives.
   Supervisor-owned or `:heir`-configured. Type matches intent.
5. **Binary parser bounds.** Every attacker-controlled `size`
   validated against `byte_size(rest)` BEFORE the match.
6. **No `Code.eval_*` on untrusted input.** Hot-code-reload
   restricted to operator-privileged paths.
7. **Distribution hygiene.** Long random cookie from
   `/dev/urandom`. epmd bound to localhost. TLS distribution for
   cross-host clusters.
8. **Port.open form.** Always `:spawn_executable` with `args:`.
   `System.cmd/3` preferred.
9. **NIF safety.** Dirty schedulers for >1ms work. Rust + Rustler
   with `panic = "catch"`.
10. **Phoenix CSRF + session.** `:browser` pipeline includes CSRF.
    `:secret_key_base` from runtime env. Channel `handle_in/3`
    re-authorizes.
11. **Ecto fragment discipline.** No `unsafe_fragment/1` without
    justification. `Repo.query!/3` uses parameter list.
12. **Crypto.** `:crypto.strong_rand_bytes/1` for tokens; `:rand`
    only for simulation. Argon2/Bcrypt/Pbkdf2 for passwords. SSL
    clients use `verify: :verify_peer` with CA bundle.

### Variant analysis: Gleam

Statically-typed ML-family BEAM language compiling to BEAM
bytecode (or JS). The type system catches the GenServer state-
not-threaded bug (callback return forces new state), most
pattern-match-on-untrusted-binary bugs (sized integer types force
explicit bounds), and the selective-receive-never-matches pattern
(`process.receive` takes a `Selector(a)` whose type guards
exhaustiveness). Gleam does NOT solve atom-table exhaustion
(Gleam atoms hit the BEAM atom table), distribution-cookie
footgun (same wire protocol), NIF crash, or ETS hazards. Partial
mitigation — raises the language discipline floor but doesn't
address runtime footguns.

### Variant analysis: LFE (Lisp Flavoured Erlang)

Robert Virding's Lisp-syntax BEAM language. Same runtime, same
footguns. From a security audit perspective, LFE is Erlang; treat
it identically. The Lisp-homoiconic macro system requires
particular scrutiny around macro-expansion-to-eval primitives.

### Variant analysis: AtomVM (BEAM for microcontrollers)

Reduced-footprint BEAM for ESP32, RP2, MCU targets. Atom table is
smaller (exhaustion trivially fast). No distribution protocol
(cookie footgun doesn't apply). NIFs are more dangerous (no MMU
on most targets — a NIF crash takes down the device). ETS may not
be available; Mnesia definitely not. Treat AtomVM audits as
embedded-systems audits with BEAM flavors; lean on
[[reference-firmware-embedded-security]].

### When to defer to other docs

- **BEAM `term_to_binary`/`binary_to_term`** —
  [[reference-deserialization-expertise]]. `binary_to_term` on
  untrusted bytes is RCE-equivalent (term constructor allocates
  arbitrary atoms and reference-counted resources).
- **Audit recipes** — [[reference-code-review-expertise]] (apply
  click-count + auth-homogeneity to every Phoenix controller /
  GenServer / Channel).
- **Concurrency** — [[reference-race-conditions-concurrency]].
- **SQL dialect peculiarities** —
  [[reference-sql-dialect-footguns]] (Postgrex, MyXQL, Exqlite).
- **Shell injection generic** — [[reference-shell-injection]].

Sources: Gleam documentation (`gleam.run`), LFE site (`lfe.io`),
AtomVM site (`atomvm.org`), Sobelow `ignore` pragma
documentation, EEF Security WG
(`security.erlef.org`), `appsec.guide` BEAM section.

---

## 14. References

### Official BEAM / OTP documentation

- Erlang/OTP docs hub — `erlang.org/doc`
- `:erlang` BIFs — `erlang.org/doc/apps/erts/erlang.html`
- `ets` — `erlang.org/doc/apps/stdlib/ets.html`
- `:crypto` — `erlang.org/doc/apps/crypto/crypto.html`
- `:public_key` — `erlang.org/doc/apps/public_key/public_key.html`
- `:ssl` — `erlang.org/doc/apps/ssl/ssl.html`
- NIFs — `erlang.org/doc/system/nif.html`
- Bit Syntax — `erlang.org/doc/system/bit_syntax.html`
- Binary handling — `erlang.org/doc/system/binaryhandling.html`
- Elixir `Code`, `Port`, `GenServer`, `Task`, `Agent`, `Registry`,
  `Process` — `hexdocs.pm/elixir`
- Phoenix.LiveView — `hexdocs.pm/phoenix_live_view`
- Phoenix.Token — `hexdocs.pm/phoenix/Phoenix.Token.html`
- Plug.CSRFProtection — `hexdocs.pm/plug/Plug.CSRFProtection.html`
- Ecto.Query.API — `hexdocs.pm/ecto/Ecto.Query.API.html`

### EEF Security Working Group

- EEF Security WG site — `security.erlef.org`
- Preventing atom exhaustion —
  `security.erlef.org/secure_coding_and_deployment_hardening/atom_exhaustion.html`
- Spawning external executables —
  `erlef.github.io/security-wg/secure_coding_and_deployment_hardening/external_executables.html`
- EEF CNA CVE catalog — `cna.erlef.org/cves/`
- CVE-2026-32688 (plug_cowboy atom exhaustion)
- CVE-2026-42793 (absinthe atom exhaustion)

### Researcher-authored references

- Armstrong KTH 2003 thesis —
  `erlang.org/download/armstrong_thesis_2003.pdf`
- Fred Hebert *Learn You Some Erlang* — `learnyousomeerlang.com`
- Fred Hebert *Erlang in Anger* — `erlang-in-anger.com`
- Saša Jurić *Elixir in Action* 3rd ed., Manning 2024
- Saša Jurić "The Erlangelist" — `theerlangelist.com`
- José Valim's Dashbit blog — `dashbit.co/blog`

### Security vendors and tools

- Sobelow — `github.com/sobelow/sobelow`, docs `hexdocs.pm/sobelow`
- Paraxial.io blog — `paraxial.io/blog` (atom-DoS, RCE, SQLi,
  Sobelow guides)
- Credo — `github.com/rrrene/credo`
- Dialyxir — `github.com/jeremyjh/dialyxir`
- recon — `github.com/ferd/recon`
- pobox — `github.com/ferd/pobox`
- Rustler — `github.com/rusterlium/rustler`, `docs.rs/rustler`

### Distribution / cluster security advisories

- Insinuator "Erlang distribution RCE and a cookie bruteforcer"
  (2017-10) — `insinuator.net/2017/10/...`
- exploit-db 49418, 46024
- Rapid7 module `exploit/multi/misc/erlang_cookie_rce`
- gteissier/erl-matter — `github.com/gteissier/erl-matter`
- Security Boulevard "Erlang Authenticated Remote Code Execution"
  (2018-09)

### NIF / FFI and mailbox diagnostics

- Andrea Leopardi "Using C from Elixir with NIFs" —
  `andrealeopardi.com/posts/using-c-from-elixir-with-nifs/`
- beam-wisdoms BIF vs NIF — `github.com/kvakvs/beam-wisdoms`
- Erlang Solutions "Receiving messages in Elixir" —
  `erlang-solutions.com/blog/`

### Variant BEAM languages

- Gleam — `gleam.run`
- LFE — `lfe.io`
- AtomVM — `atomvm.org`
- Caramel — `caramel.run`

### Cross-link landing pages

- `code_review_expertise.md` §"Click-count severity," §"Auth-
  homogeneity audit"
- `semgrep_rule_authoring.md` §"Generic-mode patterns"
- `race_conditions_concurrency_expertise.md` §"Structured
  concurrency," §"Back-pressure"
- `shell_injection_expertise.md` §"argv vs string-shell"
- `sql_dialect_footguns_expertise.md` §"PostgreSQL," §"MySQL"
- `cryptography_expertise.md` §"PRNG selection," §"Cert validation"
- `cicd_supply_chain_expertise.md` §"Hex.pm supply chain"
- `deserialization_expertise.md` §"BEAM term_to_binary"
- `firmware_embedded_security.md` §"BEAM on microcontrollers"
- `distributed_authz_expertise.md` §"CWE-862 / CWE-863"
