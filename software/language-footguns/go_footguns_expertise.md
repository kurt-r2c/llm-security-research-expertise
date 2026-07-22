# Go Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from the Go core team, Google Go Security, Geomys, and the institutional researchers that catalog Go-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — cataloguing primitives whose
> *default behavior* in a specific language ecosystem is unsafe, distinct from
> cross-language bug-class docs (SQL injection, deserialization, shell injection,
> path traversal) that cover attack surface by class rather than by language.
> The 2024-2026 load-bearing updates: Go 1.22's per-iteration loop-variable
> scope (the decade-old loop-variable-capture footgun is finally fixed for
> code that opts in via `go 1.22` in `go.mod`, but every pre-1.22 codebase
> still carries the bug); Go 1.22's `net/http.ServeMux` method-and-wildcard
> routing (the prior path-prefix matching surface is now optional, but legacy
> handlers retain the old behavior); Go 1.21's perfectly-reproducible toolchain
> bootstrap (Russ Cox's multi-release push that closed the trusted-builder gap
> in the Go supply chain); Go 1.26's built-in goroutine-leak profile (the first
> first-class diagnostic for leaked goroutines, joining `synctest` from 1.24);
> govulncheck v1.0.0 (2023) and its 2024-2026 integration into the standard
> Go developer surface; the 2025 `mholt/archiver` and HashiCorp `go-slug`
> Zip-Slip disclosures (CVE-2025-3445, HCSEC-2025-01) demonstrating that the
> 2018 Snyk-named bug class is still actively shipping in Go libraries;
> Filippo Valsorda's transition from Google Go Security lead to Geomys
> (independent professional maintainer of the Go cryptography standard
> library); the continued slow burn of `unsafe.Pointer` / `cgo` lifetime
> bugs in production Go codebases that touch native interfaces.
>
> **Researchers:**
> - **Rob Pike** — Go co-creator (with Robert Griesemer and Ken Thompson,
>   2007 at Google; public release 2009); the design rationale for Go's
>   minimalist surface (no inheritance, no generics until 1.18, no exceptions,
>   `defer` instead of try/finally, goroutines instead of threads) is in
>   his "Go at Google" / "Less is exponentially more" / "Concurrency is not
>   parallelism" talks; co-designer of UTF-8 and the Plan 9 operating
>   system at Bell Labs; long career documenting how a deliberately
>   minimal language surface still produces a non-trivial footgun catalog
> - **Robert Griesemer** — Go co-creator; Swiss computer scientist (ETH
>   Zurich, doctoral student of Niklaus Wirth); before Go, worked on
>   Google's V8 JavaScript engine, Sawzall, the Java HotSpot virtual
>   machine, and Strongtalk; remains a principal engineer at Google on
>   Go language evolution
> - **Russ Cox** — Go technical lead from inception through 2024;
>   architect of the Go module system (vgo / Go modules), the
>   `go.sum` checksum-database transparency log, the `proxy.golang.org`
>   module proxy, and the perfectly-reproducible Go 1.21 toolchain
>   bootstrap (the multi-release effort that closed the trusted-builder
>   gap); maintains the `research!rsc` blog at `research.swtch.com`
>   with deep-dive posts on supply-chain security, reproducible builds,
>   and the Go ecosystem's design rationale; subsequently advocated
>   publicly for the broader supply-chain-security agenda after
>   stepping back from the tech-lead role
> - **Filippo Valsorda** — founder of Geomys (the professional
>   maintenance firm for Go cryptography); maintainer of the Go
>   cryptography standard library since 2018, first at Google (where
>   he led the Go Security team) and now as an independent full-time
>   maintainer; co-designer of the Go Checksum Database (with Russ
>   Cox); contributor to the TLS 1.3 design; author of the `age` file
>   encryption tool, the `mkcert` development certificate generator,
>   and the `yubikey-agent` SSH agent; long-running blog at
>   `words.filippo.io` covering Go-cryptography internals, the Geomys
>   "standard of care" maintenance model, and the Go-supply-chain
>   advocacy that runs alongside Cox's work
> - **Dmitry Vyukov** — Principal Software Engineer at Google;
>   architect of ThreadSanitizer (the LLVM-instrumented data-race
>   detector that powers Go's `-race` build flag), `syzkaller` (the
>   coverage-guided system-call fuzzer that has found 5000+ Linux
>   kernel bugs), `go-fuzz` (the coverage-guided fuzzer for Go, the
>   spiritual predecessor to the in-tree `testing.F` fuzzing API
>   added in Go 1.18), and `GoSmith` (random Go program generator);
>   the canonical "Slaughtering Data Races" / TSan corpus is the
>   source for understanding what Go's race-detector actually does
>   and does not catch
> - **Kris Nóva** (1985-2022) — Engineer at GitHub and prior Open
>   Source Lead at Sysdig (Falco), Heptio, and Microsoft Azure; co-author
>   of *Cloud Native Infrastructure* (O'Reilly 2017), author of
>   *Hacking Capitalism* (2022); co-founder of the Cluster API project,
>   creator of Kubicorn and `naml`; long-running Go-and-Linux-kernel
>   security writing and conference talks; passed away in 2022 but
>   the body of work on Kubernetes-Go security, `eBPF`, and the
>   container runtime surface remains a foundational reference
> - **Eli Bendersky** — Senior software engineer at Google; long-running
>   technical writer at `eli.thegreenplace.net` covering Go, compilers,
>   and systems programming; the canonical "Beware of copying mutexes
>   in Go," "Better HTTP server routing in Go 1.22," and "Reading and
>   writing JSON with concurrent goroutines" posts that establish the
>   field's vocabulary for Go-specific footguns
> - **Dave Cheney** — long-running independent Go contributor and
>   technical writer at `dave.cheney.net`; the canonical "Typed nils
>   in Go 2," "Don't just check errors, handle them gracefully," and
>   "Channel axioms" posts; co-organizer of GopherCon AU; reference
>   for the nil-interface-vs-nil-pointer distinction and for the
>   `errors.Is` / `errors.As` / `%w` discipline
> - **Trail of Bits Go team** — security research firm with a long
>   corpus of Go audits (Cosmos / Tendermint, Ethereum-Go clients,
>   the Hyperledger Fabric chaincode runtime); authors of the
>   "Security assessment techniques for Go projects" blog series;
>   contributors to `go-fuzz` improvements; the `Testing Handbook`
>   at `appsec.guide` consolidates the Go-audit doctrine; the
>   `gosec` / `staticcheck` / `golangci-lint` configuration baseline
>   that Trail of Bits ships is widely adopted as the floor for
>   Go-codebase static analysis
> - **Google Go Security Team** — institutional contributor; ships
>   `govulncheck` (the call-graph-aware vulnerability scanner backed
>   by the curated Go vulnerability database at `vuln.go.dev`,
>   announced September 2022, v1.0.0 July 2023); coordinates Go-core
>   CVE response; publishes Go-security advisories with reachability
>   analysis rather than dependency-tree heuristics; co-author with
>   Russ Cox of the "Vulnerability Management for Go" announcement
>   that established the Go-ecosystem CVE-coordination model
>
> **Institutional contributors:** Google Go team (the canonical
> `go.dev` blog corpus, the Go vulnerability database at `vuln.go.dev`,
> the `golang.org/x/tools` `cmd/vet` / `cmd/govulncheck` toolchain);
> Geomys (`age`, `mkcert`, `yubikey-agent`, and the Go cryptography
> standard-library maintenance contract); MITRE CWE (CWE-362, CWE-22,
> CWE-78, CWE-330, CWE-327, CWE-502, CWE-117, CWE-200, CWE-755); Snyk
> (the 2018 Zip-Slip vulnerability disclosure naming the bug class
> and the ongoing Go-CVE corpus); JFrog Security Research
> (the `mholt/archiver` Zip-Slip CVE-2025-3445 disclosure and the
> running Go-vulnerability database); HashiCorp Security
> (the `go-slug` HCSEC-2025-01 advisory); the Open Source Security
> Foundation (OpenSSF) supply-chain working groups that codify the
> Go ecosystem's threat model.
>
> **What this doc is NOT:** not a Go language tutorial, not a
> replacement for cross-language bug-class guidance, not a substitute
> for `go vet`, `staticcheck`, `golangci-lint`, `gosec`, or
> `govulncheck`. It is the Go-specific layer beneath cross-language
> audit heuristics. Read this before reviewing any non-trivial Go
> codebase; read `code_review_expertise.md` for the click-count
> severity heuristic that lifts each footgun into a triage decision.

Cross-links: `race_conditions_concurrency_expertise.md` for the
cross-language concurrency surface (Go's `sync.Mutex` copy and
loop-variable-capture footguns are the Go incarnations of the broader
race-condition / shared-state bug class); `shell_injection_expertise.md`
for the `os/exec` and `exec.Command("sh", "-c", ...)` surface;
`cryptography_expertise.md` for the cross-language crypto-primitive
discipline that `crypto/*` participates in; `cicd_supply_chain_expertise.md`
for the `go install repo@latest` / module-proxy / `replace` directive
surface; `supply_chain_provenance_expertise.md` for the reproducible-build
and checksum-database guarantees Russ Cox built into Go; `code_review_expertise.md`
for the click-count severity heuristic and the candidate-point auditing
methodology; the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for detection-rule authoring
guidance; `firmware_embedded_security.md` for the `unsafe.Pointer` /
`cgo` adjacency where Go meets the native ABI; `deserialization_expertise.md`
for the `encoding/gob` and `encoding/json` `interface{}` target surface
that mirrors the cross-language deserialization bug class.

---

## 1. The behavioral-footgun framing

### 1.1 Go's "simplicity" claim vs the surface that exists anyway

Go is marketed as the simple language: 25 keywords, no inheritance,
no generics until 1.18, no exceptions, no operator overloading,
garbage collection, structural typing via interfaces. Rob Pike's
"Less is exponentially more" essay frames the entire language as a
deliberate push-back against the C++ / Java surface area.

That marketing is true in a narrow sense — Go's parse surface is
smaller, the standard library's API shapes are more uniform — and
misleading in the security-relevant sense. *Every footgun in this
document* satisfies the criterion: **the Go compiler accepts the
code without warning, the default tooling does not flag it (or flags
it only with non-default static-analyzer opt-ins), the runtime
executes it producing the unsafe behavior**. The simplicity is at
the surface; the semantics underneath include nil-interface-vs-nil-
pointer asymmetry, slice-aliasing through shared backing arrays,
mutex value-copy that silently breaks locking, goroutine leaks that
consume memory forever, channel-close panics, `defer` evaluation
order that holds memory until function return, and a host of others.

The behavioral-footgun framing applies in full force. A *bug class*
answers "what kind of vulnerability is this." A *behavioral footgun*
answers "what does this Go primitive *do*, such that ordinary use
produces a bug class without the developer noticing." `sync.Mutex`
embedded by value is not a bug class — it is a primitive whose
default behavior breaks mutual exclusion when the containing struct
is passed by value. `json.Unmarshal(data, &v)` is not a bug class —
its default behavior silently ignores unknown fields, enabling
polyglot-input attacks. `exec.Command("sh", "-c", userInput)` is
not a bug class — it is a primitive whose default behavior is shell
injection.

### 1.2 The nil-interface vs nil-pointer asymmetry as the canonical example

Go's most-cited footgun is the nil-interface-vs-nil-pointer
distinction. An interface value in Go is a two-word structure: a
*type descriptor* and a *value pointer*. An interface is `nil` only
when *both* words are zero. Assigning a typed nil pointer to an
interface variable produces an interface that is not nil — the type
descriptor is populated even though the value pointer is zero. The
canonical buggy pattern:

```go
func mayFail() error {
    var err *MyError = nil
    if /* condition */ { err = &MyError{...} }
    return err  // bug: returned error is not nil even when err is nil
}
if err := mayFail(); err != nil { /* always entered */ }
```

The compiler accepts the code. `go vet` does not flag it by default.
The footgun has caused real-world incidents where error-wrapping
discipline silently propagates a typed-nil pointer through several
function boundaries before reaching a caller that compares against
untyped nil. It is a language-level semantic that cannot be removed
without breaking backwards compatibility — the subject of multiple
unaccepted Go-2 proposals. Cross-link to `code_review_expertise.md`
§"Click-count severity": typed-nil-as-error is zero-click; the
blast radius depends on what the caller does with the falsely-non-
nil error.

### 1.3 The audit-cost asymmetry

The developer writes `sync.Mutex` as a struct field once. The
auditor reads every struct that embeds `sync.Mutex` *and* every
method that operates on a value receiver of that struct. `go vet`'s
`copylocks` checker catches some copies; not all. Generics (Go
1.18+) and the new `range func` iterator shapes (Go 1.23+) add new
ways to inadvertently copy a struct, and the vet rules have not
fully caught up. Each footgun is a detection target, not just a
coding antipattern.

---

## 2. nil interfaces vs nil pointers

### 2.1 The two-word interface representation

An interface value in Go is laid out as a pair of pointers (in the
runtime, `(*itab, unsafe.Pointer)`): the first word identifies the
*concrete type* and method set; the second word points to the
concrete value (or, for value types fitting in a word, may hold the
value directly). An interface is `nil` if and only if both words
are zero. The Go spec is explicit on this point: a nil-pointer
value, when assigned to an interface variable, fills in the type
word — and the interface is no longer nil.

```go
var p *T  // typed nil pointer; p == nil is true
var i interface{} = p
// i == nil is FALSE
// reflect.ValueOf(i).IsNil() is TRUE
// the asymmetry is the bug surface
```

The "go tour" page at `go.dev/tour/methods/12` covers the basics but
does not warn about the production consequences. Dave Cheney's
"Typed nils in Go 2" is the canonical writeup of the audit pattern.

### 2.2 The `error` return-type incarnation

`error` is the standard library's most-used interface. The
typed-nil-pointer-returned-as-error pattern is *the* canonical
incarnation. The historical fix is to return untyped nil explicitly:

```go
func DoThing() error {
    var err *MyError
    if cond { err = &MyError{...} }
    if err != nil { return err }
    return nil  // explicit untyped nil
}
```

Some checkers (`nilerr`, `nilness` in `golang.org/x/tools/go/analysis/passes/nilness`,
custom Semgrep patterns) catch a subset. None catch all.

### 2.3 `errors.Is` and `errors.As` precise-type matching

The Go 1.13+ wrapping primitives (`fmt.Errorf("...: %w", err)`,
`errors.Is(err, target)`, `errors.As(err, &target)`) interact with
the typed-nil footgun in non-obvious ways. Direct comparison
`err == sentinel` fails when the error has been wrapped;
`errors.Is(err, sentinel)` walks the chain via `Unwrap()`. Code
that does `if err == os.ErrNotExist` silently misses a wrapped
`os.ErrNotExist`. Migrate to `errors.Is`.

The `errors.As` discipline is to declare a *pointer to the target
type* and pass that:

```go
var pathErr *fs.PathError
if errors.As(err, &pathErr) { /* matched */ }
```

The standard library panics on some misuses but not all.

### 2.4 `reflect.ValueOf(i).IsNil()` vs `i == nil`

When the typed-nil footgun reaches a generic interface-typed
parameter, neither `i == nil` nor `i != nil` gives the right answer.
The standard recipe uses `reflect.ValueOf(i).IsNil()` after a kind
check. Defensive use of `reflect` adds cost (~100x slower than
direct comparison); the preferred fix is to eliminate the
typed-nil-returned-as-interface antipattern at the source.

---

## 3. Goroutine leaks and channel mistakes

### 3.1 The goroutine-leak axiom

A goroutine has leaked when it is in a state it can never exit:
parked on a channel send or receive, on a mutex acquire, on a
`sync.Cond.Wait`, or on a `select` with no ready case and no
default. The Go runtime does not reap stuck goroutines; they sit
in the scheduler forever, consuming stack memory and runtime
tables. A long-running server that leaks one goroutine per request
will exhaust memory in hours-to-days. Detection is hard because
`runtime.NumGoroutine()` rises but the *cause* is at the call site
that started the leaked goroutine, which may be far from the
symptom.

Go 1.24 added the `testing/synctest` package for deterministic
goroutine-leak detection in tests. Go 1.26 added a built-in
goroutine-leak profile to `runtime/pprof`. Before those, the
detection state of the art was `uber-go/goleak`.

### 3.2 The forgotten-sender pattern

```go
func process(work []Item) []Result {
    ch := make(chan Result)  // unbuffered
    for _, item := range work {
        go func(item Item) { ch <- compute(item) }(item)  // blocks if no receiver
    }
    var results []Result
    for i := 0; i < len(work); i++ {
        select {
        case r := <-ch:
            results = append(results, r)
        case <-time.After(timeout):
            return results  // unsent goroutines leak forever
        }
    }
    return results
}
```

Fixes: buffered channel of `len(work)` capacity; or
`context.WithTimeout` with workers selecting on `ctx.Done()`; or
`golang.org/x/sync/errgroup` for structured concurrency.

### 3.3 `close()` panics

`close()` on a nil channel, an already-closed channel, or a send
on a closed channel all panic. The Go runtime makes no attempt to
recover; the panic kills the program unless caught by a `recover()`
in a deferred function. The defensive shape is "the *sender*
closes the channel, never the receiver, and the sender closes the
channel exactly once." Composite shapes (multiple senders fanning
into one channel) require external coordination — typically a
`sync.Once` to serialize the close, or a separate "done" channel
that signals no more sends. Tony Bai's "Channel axioms" and Dave
Cheney's blog formalize this discipline.

### 3.4 The for-range over closed-channel pattern

Receiving from a closed channel returns the zero value *forever*.
Idiomatic `for v := range ch` terminates when `ch` is closed and
drained; `for { v := <-ch; ... }` does not — it spins forever
consuming zero values. Use `for v := range ch` or the comma-ok
form: `for { v, ok := <-ch; if !ok { break }; ... }`.

### 3.5 WaitGroup discipline

`defer wg.Done()` as the first line of every WaitGroup-tracked
goroutine, before any early-return possibility. `wg.Add` must be
called *before* the goroutine starts (or before the parent can
call `wg.Wait`); calling `wg.Add` inside the spawned goroutine is
a race that the race-detector catches with `-race`.

### 3.6 Context-cancellation discipline

Every goroutine that does I/O or blocks on a channel should accept
a `context.Context` and `select` on `ctx.Done()` in addition to
its primary channel. The footgun is the single-select shape that
*only* watches `in` — if the caller cancels `ctx`, the worker
never sees it and continues to block. Detection: every long-running
goroutine that does not have a `case <-ctx.Done()` clause in every
blocking select is a leak candidate.

Cross-link to `race_conditions_concurrency_expertise.md` for the
broader structured-concurrency framing.

---

## 4. Mutex copy and sync primitive footguns

### 4.1 `sync.Mutex` copied by value — silently broken locking

A `sync.Mutex` is a value type. Copying a mutex creates two
separate mutexes — the lock on the original does not exclude code
holding the lock on the copy:

```go
type Counter struct {
    mu sync.Mutex
    n  int
}

func (c Counter) Increment() {  // value receiver — c is a COPY
    c.mu.Lock(); defer c.mu.Unlock()
    c.n++  // also operates on the copy
}
```

`go vet`'s `copylocks` checker catches this case. The fix is a
pointer receiver `func (c *Counter) Increment()`. Audit pattern:
every struct embedding `sync.Mutex`, `sync.RWMutex`,
`sync.WaitGroup`, or `sync.Cond` should be passed by pointer.
Returning the struct by value, passing it to a function by value,
or copying it via `=` all break the lock. Eli Bendersky's "Beware
of copying mutexes in Go" is the canonical writeup.

### 4.2 The `noCopy` marker and `vet` blind spots

The Go standard library uses an unexported `noCopy` struct with
dummy `Lock()` / `Unlock()` methods to mark types that must not be
copied; `copylocks` flags any embedded `sync.Locker`. Library
authors can adopt the same trick. `copylocks` does *not* catch
every shape — copies through `interface{}` or generic type
parameters (Go 1.18+) may evade the checker. Defensive posture:
`go vet ./...` as a CI gate; treat generics as a potential
blind spot.

### 4.3 `sync.Once.Do(f)` — panic prevents re-execution

```go
var once sync.Once
once.Do(func() { panic("first call panics") })
once.Do(func() { /* NEVER CALLED — Once marks itself done even on panic */ })
```

`sync.Once` marks itself complete *before* invoking the function.
If the function panics, the `Once` refuses to invoke any future
`Do(f)`. The defensive shape is to make the function infallible
or use a guarded `init` flag with explicit error checking.

### 4.4 `atomic.Value.Store` of different concrete types — panic

```go
var v atomic.Value
v.Store("hello")
v.Store(42)  // panic: sync/atomic: store of inconsistently typed value
```

The fix is `atomic.Pointer[T]` (Go 1.19+) which is type-parameterized
and enforces the constraint at compile time, or to wrap
heterogeneous values in a common interface.

### 4.5 `sync.Map` vs `map + sync.Mutex`

`sync.Map` is optimized for two specific patterns: keys written
once and read many times; goroutines operating on disjoint key
sets. Outside those patterns, a plain `map[K]V` guarded by
`sync.Mutex` (or `sync.RWMutex` for read-heavy workloads) is
faster and provides type safety. The `sync.Map` API uses
`interface{}`, losing compile-time type checking and adding an
allocation per operation.

Cross-link to `race_conditions_concurrency_expertise.md` §"Shared
state and ownership."

---

## 5. defer and loop-variable captures

### 5.1 `defer` evaluation order

`defer f()` evaluates `f`'s *arguments* at the defer statement,
then queues the call on the function-return stack. Deferred calls
run in LIFO order when the function returns:

```go
for i := 0; i < 10; i++ {
    f, err := os.Open(files[i])
    if err != nil { continue }
    defer f.Close()  // FOOTGUN: all closes happen at function return
    // ... use f
}
```

File handles accumulate until the enclosing function returns —
which may be never for a long-running service-loop. The fix is to
move the loop body into a function so each iteration gets its own
defer scope.

### 5.2 Goroutine + loop-variable capture (pre-Go-1.22)

```go
for i := 0; i < 10; i++ {
    go func() { fmt.Println(i) }()  // pre-1.22: most goroutines print 10
}
```

Before Go 1.22, the loop variable was a *single* variable scoped
to the entire loop; closures captured a reference to that single
variable. The historic fix was either to shadow (`i := i`) or to
pass `i` as a parameter. Go 1.22 changed semantics: when the
module's `go.mod` declares `go 1.22+`, each iteration gets its
own scoped copy. Mixed codebases with pre-1.22 modules retain the
old behavior. Audit pattern: any `go func` (or `defer` capturing
`i`) inside a `for` loop in a pre-1.22 module is a bug candidate.

### 5.3 `for k, v := range map` — order not guaranteed

The Go runtime randomizes iteration order on each map traversal to
prevent applications from relying on it. Tests that depend on map
iteration order are flaky; security-sensitive "first match wins"
logic with a map-of-rules is non-deterministic. Fix: extract keys
into a slice, sort, then iterate the sorted slice.

### 5.4 Map deletion during iteration

Deleting unvisited entries during iteration is well-defined and
safe. *Creating* entries during iteration may or may not include
them, depending on runtime details. Audit pattern: any `m[k] = v`
inside a `range m` loop is a hazard.

---

## 6. Slice and map aliasing surprises

### 6.1 Slices share backing arrays

A slice is a three-word header: pointer to backing array, length,
capacity. A sub-slice `s[a:b]` shares the backing array with the
parent. Modifications are visible across all sharing slices. The
aliasing extends through `append`: if the slice has spare capacity,
`append` writes into the shared backing array; if capacity is
exhausted, `append` allocates and the alias is broken. The same
call site may or may not alias depending on runtime state.

### 6.2 The three-index slice expression

The defensive primitive is `s[low:high:max]` which sets both length
and capacity: `sub := s[1:3:3]` produces a slice with length 2 and
capacity 2 — any `append(sub, ...)` reallocates. Audit pattern:
any function that returns a sub-slice of its input should consider
whether the caller can safely modify the result. If the contract
is "I am returning a logically-distinct slice," use
`s[low:high:high]` or `append([]T{}, s[low:high]...)`.

### 6.3 `append()` reallocates non-deterministically

Current Go runtimes double capacity until ~1024 elements then grow
by ~25%. The exact algorithm is subject to tuning. Two slices that
share a backing array *may* desync after an `append` or *may not* —
don't depend on either outcome.

### 6.4 nil maps are read-only — write panics

```go
var m map[string]int  // nil map; m == nil is true
_ = m["foo"]          // OK; returns zero value
m["foo"] = 1          // panic: assignment to entry in nil map
```

Reads from a nil map return the zero value (same as empty map);
writes panic. A struct field that is a map, not explicitly
initialized, is nil and panics on first write. Fix: initialize at
construction time with `make(map[K]V)`. The `go vet` `nilness`
analyzer flags some cases.

### 6.5 nil slices vs empty slices

A nil slice (`var s []int`) and an empty slice (`s := []int{}`)
behave almost identically: both have `len(s) == 0`, both range,
both append. Asymmetries:

- `s == nil` distinguishes them.
- `json.Marshal(nilSlice)` produces `null`; `json.Marshal(emptySlice)`
  produces `[]` — security-relevant when the consumer is a
  schema-validating client.
- `reflect.DeepEqual(nilSlice, emptySlice)` is false.

Prefer `len(s) == 0` checks except when the nil-vs-empty
distinction is semantically meaningful.

### 6.6 `make([]T, 0, 100)` vs `make([]T, 100)`

`make([]T, n)` creates a slice with length n, all zero-initialized.
`make([]T, 0, n)` has length 0 and capacity n. The footgun:

```go
results := make([]int, len(input))  // length, all zero
for i, v := range input {
    if predicate(v) { results = append(results, compute(v)) }  // appends AFTER zeros
}
```

Fix: `make([]int, 0, len(input))`. Silent bug; `go vet` does not
catch it.

---

## 7. Error handling — `errors.Is`, `errors.As`, `%w`

### 7.1 `fmt.Errorf` with `%w` vs `%v`

`fmt.Errorf("doing X: %w", err)` *wraps* `err` so `errors.Is`,
`errors.As`, and `errors.Unwrap` can navigate the chain. `%v`
*renders* as a string and discards type information; consumers
downstream cannot recover the underlying error. Prefer `%w` for
error formatting unless there is a specific reason not to.

### 7.2 `errors.Is(err, sentinel)` vs `err == sentinel`

Direct comparison `err == sentinel` works only when `err` *is* the
sentinel — not when wrapped. `errors.Is` walks the chain via
`Unwrap()`. After Go 1.13, all new code should use `errors.Is(err,
os.ErrNotExist)` rather than direct comparison.

### 7.3 `errors.As(err, &target)` — typed unwrap

`errors.As` walks the chain and type-asserts each node into the
target. The target must be a *pointer to a type that implements
error* (or a pointer to an interface). The standard library panics
on some misuses but not all.

### 7.4 The "return err" pattern loses context

The Dave Cheney maxim: "Don't just check errors, handle them
gracefully." Wrap with `%w` to preserve type information *and* add
context: `return fmt.Errorf("upload: open %s: %w", path, err)`.

### 7.5 `panic` / `recover` semantics

`recover()` returns the panic value but *only when called inside a
deferred function*. The footgun is calling `recover()` directly
in the function body — it always returns nil. The recipe is the
deferred-closure form:

```go
func safe() (err error) {
    defer func() {
        if r := recover(); r != nil { err = fmt.Errorf("recovered: %v", r) }
    }()
    dangerousOp()
    return nil
}
```

### 7.6 Panic in a goroutine kills the program

`recover()` works only within the same goroutine. A panic in a
spawned goroutine cannot be caught by a deferred recover in the
parent — the panic propagates to `runtime.Goexit()` and terminates
the entire program. Long-running services that spawn workers need
each worker to install its own `defer recover` if panic-safety is
required.

---

## 8. `encoding/json` and untrusted input

### 8.1 `json.Unmarshal(data, &v)` — type confusion via interface{} target

When the target is `*interface{}` or contains `interface{}` fields,
`json.Unmarshal` decodes into Go's default representations: numbers
become `float64`, strings become `string`, booleans become `bool`,
arrays become `[]interface{}`, objects become
`map[string]interface{}`. Downstream type assertions panic on
mismatch; attacker-controlled input dictates the panic site.
Integer values arrive as `float64` — precision loss for values
larger than 2^53.

### 8.2 Unknown fields silently ignored

By default, `json.Unmarshal` ignores JSON keys that don't match any
struct field. This enables polyglot-input attacks: an attacker
provides extra fields that the application ignores but a
validation layer or audit log also ignores, producing a mismatched
view of the input. The fix is `json.Decoder.DisallowUnknownFields()`,
which makes any unknown field return an error. The trade-off is
forward-compatibility (newer clients with extra fields are
rejected), but for security-sensitive APIs the strictness is
desired.

### 8.3 Integer-as-float64 precision loss

For IDs greater than 2^53 (Twitter/X tweet IDs, snowflake IDs),
the default `float64` target silently corrupts the value.
`UseNumber()` defers parsing to a `json.Number`, which is a string
that can be converted to int64 or big.Int as needed. Always check
the error from `Int64()` / `Float64()`.

### 8.4 Custom `UnmarshalJSON` panics

Custom unmarshal methods can panic on malformed input; the panic
propagates to the caller, who may not have a recover. Audit
pattern: any custom `UnmarshalJSON` that does pointer dereferencing,
map access, or slice indexing without bounds checks is a panic
candidate.

### 8.5 Time format defaults

`time.Time` serializes to RFC 3339 by default. Custom layouts
require a wrapper type. A struct field declared as `time.Time`
that receives a non-RFC-3339 timestamp gets a zero `time.Time` or
an unmarshal error. Specify the expected format explicitly in the
API contract.

---

## 9. `net/http` and request-handling

### 9.1 `http.HandleFunc` registers on the default mux

`http.HandleFunc("/foo", h)` registers on the *package-level
default mux*, which `http.ListenAndServe(addr, nil)` serves. Any
code path in the process can register handlers. The footgun: a
transitive dependency that imports a package calling
`http.HandleFunc` in its `init` adds a publicly-accessible endpoint.
`net/http/pprof` famously does this on `/debug/pprof/` — importing
it for side effects exposes profiling that includes heap snapshots
and goroutine stacks. Audit pattern: never use the default mux in
production; construct explicit `http.NewServeMux()` and pass it.

### 9.2 `http.ServeMux` path-prefix matching (pre-1.22)

Before Go 1.22, a pattern ending in `/` matched the path and *all*
its sub-paths. A handler for `"/users/"` matched
`"/users/123/delete"` even when only `"/users/{id}"` was intended.
Go 1.22 added method-and-wildcard syntax (`"GET /users/{id}"`)
that matches one path segment and filters by method. The new
syntax is opt-in; legacy patterns retain old behavior. Audit
pattern: any `mux.HandleFunc("/path/", ...)` is a prefix-match
handler; verify the handler defends against unintended sub-path
matches.

### 9.3 `http.MaxBytesReader` for upload limits

By default, `r.Body` is unbounded — an attacker can stream
gigabytes. The defensive primitive is
`r.Body = http.MaxBytesReader(w, r.Body, 10<<20)`. Every handler
that reads `r.Body` should have explicit size limits.
`http.MaxBytesHandler` applies the limit at the middleware layer.

### 9.4 `r.Body.Close()` discipline

The server closes request bodies after the handler returns, but
response bodies (the *caller* side of `http.Get`) must be
explicitly closed or the connection is not returned to the pool.
Error-path code that does `if resp.StatusCode != 200 { return err
}` without first closing the body leaks the connection. Always
`defer resp.Body.Close()` *before* any error checks on the response.

### 9.5 `http.Server` default timeouts are unlimited — DoS surface

`http.Server{}` with no timeouts holds connections indefinitely on
slow-loris attacks. `http.ListenAndServe(addr, handler)` (the
convenience form) sets no timeouts. Any production HTTP server
should use the explicit `http.Server` struct with
`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`,
and `MaxHeaderBytes` set.

### 9.6 TLS config defaults

`tls.Config{}` zero-value verifies certificates (good); the cipher
suite list and version range have evolved across Go versions. As
of Go 1.22, the default minimum is TLS 1.2. The footgun is
`InsecureSkipVerify: true` which disables verification entirely —
typically introduced as a debugging convenience and forgotten.
Cross-link to `cryptography_expertise.md`.

---

## 10. `crypto/*` defaults

### 10.1 `crypto/rand` is the only cryptographic PRNG

`math/rand` is *not* cryptographic — deterministic LFSR seeded from
the system clock (pre-Go-1.20: constant seed in some contexts).
Any security-relevant token must come from `crypto/rand.Reader`:

```go
buf := make([]byte, 32)
if _, err := rand.Read(buf); err != nil { return err }
token := hex.EncodeToString(buf)
```

Audit pattern: any use of `math/rand` to generate session tokens,
CSRF tokens, password reset tokens, or cryptographic nonces is a
critical bug. Go 1.20 made `math/rand`'s global generator
auto-seeded from `crypto/rand` (eliminating the "everyone gets the
same sequence" footgun), but the output remains non-cryptographic.
The new `math/rand/v2` (Go 1.22+) clarifies the non-crypto status
in its package name.

### 10.2 `rsa.GenerateKey` size choice

1024-bit RSA has been considered insufficient since the early
2010s. NIST SP 800-57 recommends 2048-bit through 2030 and
3072-bit beyond. ECDSA P-256 or Ed25519 is preferred for new code.

### 10.3 AES mode choices

`crypto/aes` provides only the block cipher; the *mode* (CBC, CTR,
GCM) is in `crypto/cipher`. CBC requires explicit IV management
and a separate MAC (else padding-oracle attacks); ECB is never
secure for multi-block plaintexts. The recipe is GCM
(authenticated encryption); nonce reuse with the same key is
catastrophic, so the nonce must be unique per encryption.

### 10.4 `hmac.Equal` for timing-safe comparison

`hmac.Equal` and `crypto/subtle.ConstantTimeCompare` operate in
constant time. Any byte-slice comparison in an auth path (HMAC
verification, session-token compare, password-hash compare) should
use the constant-time primitive — never `==`.

### 10.5 Password hashing — `bcrypt` / `scrypt` / `argon2`

Go has no password hashing in the standard library; use
`golang.org/x/crypto/bcrypt`, `scrypt`, or `argon2`. SHA-256 of a
password is *not* password hashing — rainbow tables exist for fast
hash functions. Audit pattern: any password storage using
`sha256.Sum256(password)` or `md5.Sum(password)` (with or without
salt) is a critical bug.

### 10.6 `crypto/tls` hostname verification

`crypto/tls` verifies the server's hostname by default. The
footgun is `InsecureSkipVerify: true` which disables verification
entirely — typically introduced as a debugging convenience and
forgotten in production. Cross-link to `cryptography_expertise.md`.

---

## 11. `os/exec` and shell injection

### 11.1 `exec.Command("sh", "-c", USER_STRING)` — shell injection

```go
cmd := exec.Command("sh", "-c", fmt.Sprintf("convert %s output.png", userInput))
```

If `userInput` is `"; rm -rf /; #"`, the shell interprets the
semicolons. The fix is direct binary invocation with separate
arguments: `exec.Command("convert", userInput, "output.png")`.
`exec.Command(name, args...)` executes via `execve`; the shell is
never involved. The shell-injection class is eliminated at the API
level.

### 11.2 Argv injection still possible

Even with separate-argument invocation, certain binaries treat the
first positional argument as a flag. The canonical example is
`find`:

```go
exec.Command("find", userInput, "-name", "*.log").Run()
// userInput = "/etc -exec rm {} ;" triggers -exec
```

The defensive primitive is the `--` separator where supported
(`git`, `ssh`, `rsync`, `find`, `xargs`). Audit pattern: any binary
invocation with user-controlled positional arguments needs either
`--` or an explicit allow-list. Cross-link to
`shell_injection_expertise.md` §"Argv injection via flag positions."

### 11.3 `os.Setenv` racing with concurrent reads

`os.Setenv` mutates the process environment. Concurrent `os.Getenv`
calls from other goroutines may see old or new values
non-deterministically; the underlying libc environment is not
thread-safe on all platforms. Audit pattern: `os.Setenv` calls
after goroutines have been spawned are race candidates. Prefer
reading environment variables once at startup into a config struct.

### 11.4 `os.Open` with user-controlled paths — traversal

```go
f, err := os.Open(filepath.Join("/uploads", userFilename))
```

If `userFilename` is `"../../etc/passwd"`, `filepath.Join` resolves
to `"/etc/passwd"`. `filepath.Join` does not canonicalize or
restrict the result to be a child of the first argument. The
defensive recipe is `filepath.Clean` plus a `strings.HasPrefix`
check on the cleaned path against the base. Even that is fragile —
symlinks under `/uploads/` can resolve to arbitrary locations; the
full defense requires `filepath.EvalSymlinks`. The `os.Root` API
(Go 1.24+) provides syscall-level containment via
`os.OpenRoot("/uploads")`.

### 11.5 `filepath.Join("/base", userInput)` — absolute-input behavior

Unlike Python `os.path.join` or .NET `Path.Combine`, Go's
`filepath.Join` does *not* silently discard the first argument when
the second is absolute. It concatenates and cleans, normalizing
`..` sequences. `filepath.Join("/base", "/etc/passwd")` returns
`"/base/etc/passwd"`; `filepath.Join("/base", "../etc/passwd")`
returns `"/etc/passwd"`. The Go behavior is safer than Python/.NET
for the absolute-argument case but still vulnerable to relative
traversal via `..`.

---

## 12. Path-traversal and filesystem

### 12.1 `filepath.Clean` semantics

`filepath.Clean(path)` lexically normalizes the path:
- Multiple slashes collapse to one
- `.` elements are removed
- `..` elements are resolved against their predecessor *if possible*
- Trailing slashes are removed (except for the root)

The footgun: `Clean` is purely lexical and does not consult the
filesystem. `filepath.Clean("/etc/../etc/passwd")` returns
`"/etc/passwd"`, which is what you want — but
`filepath.Clean("/uploads/../etc/passwd")` also returns
`"/etc/passwd"`, escaping the `/uploads` constraint. Cleaning the
path is necessary but not sufficient for containment.

### 12.2 `filepath.Walk` symlink-following defaults

`filepath.Walk` does *not* follow symlinks by default — it reports
the symlink itself with `info.Mode()&os.ModeSymlink` set, and does
not descend through it. `filepath.WalkDir` (Go 1.16+) has the same
default. The footgun is reversed: `os.ReadFile(filepath.Join(base,
userPath))` *does* follow symlinks. If an attacker can plant a
symlink anywhere under `base` pointing to `/etc/passwd`, a
subsequent `ReadFile` reads the target.

The defense: `os.Lstat` to check for symlinks before opening, or
use the `os.Root` API for syscall-level containment, or use
`filepath.EvalSymlinks` to canonicalize the target before the
prefix check.

### 12.3 `os.MkdirAll` mode bits

`os.MkdirAll(path, mode)` creates directories with the specified
mode *masked by the process umask*. The footgun:

```go
os.MkdirAll("/var/lib/myapp/data", 0700)  // may create with 0700 & ~umask
```

If the umask is the typical `022`, the result is `0700 & ~022 =
0700`. If the umask is `077`, the result is `0700 & ~077 = 0700`.
But if the umask is `0`, the mode is exactly `0700`. The umask is
process-global state and can be altered by any goroutine. For
sensitive directories, explicitly `os.Chmod` after `MkdirAll` to
ensure the mode is what you want.

### 12.4 `archive/zip` and `archive/tar` extraction → Zip/Tar Slip

The Zip Slip class (Snyk 2018) is alive in Go. If a zip entry's
name is `"../../etc/passwd"`, naive extraction writes there. The
defense is a prefix-check on `filepath.Clean(filepath.Join(base,
f.Name))` against the base path on *every* extracted entry. Recent
CVEs: CVE-2025-3445 (mholt/archiver), HCSEC-2025-01 (HashiCorp
go-slug). The bug class has been known since 2018; new Go libraries
still ship it.

Tar adds complications: entries can be symlinks or hardlinks. The
`Linkname` field can contain `..` sequences and escape the
extraction root. A two-stage attack: extract a symlink pointing
outside the root, then extract a file *through* the symlink. The
defense requires checking both `Name` and `Linkname`, refusing
absolute paths and `..` sequences in either, and ideally extracting
with `os.Root` (Go 1.24+).

### 12.5 `os.OpenFile` with `O_CREATE` race

The `O_CREATE` flag is *not* atomic with respect to other
filesystem operations. A TOCTOU attacker can replace the path with
a symlink between the existence check and the open. The defense is
`O_EXCL` combined with `O_CREATE`; for temp files, prefer
`os.CreateTemp` which uses `O_EXCL` internally.

---

## 13. `unsafe.Pointer` and `cgo`

### 13.1 `unsafe.Pointer` — type-system escape

`unsafe.Pointer` converts to/from any pointer type and to/from
`uintptr`. The `unsafe` package documents four valid patterns;
anything else is undefined behavior. The canonical footgun:

```go
p := &struct{ x, y int }{1, 2}
u := uintptr(unsafe.Pointer(p))
runtime.GC()                    // GC may move the object
q := (*int)(unsafe.Pointer(u))  // pointing at the OLD location
*q = 99                         // undefined behavior
```

`uintptr` is not a managed pointer; the GC does not update it.
Holding a `uintptr` across a GC boundary, even implicitly via a
function call that may trigger GC, is undefined behavior. The
valid arithmetic pattern is a single expression:
`p := unsafe.Pointer(uintptr(unsafe.Pointer(&s[0])) + unsafe.Sizeof(s[0]))`.
`unsafe.Slice` (Go 1.17+) and `unsafe.SliceData` (Go 1.20+) provide
a structured API and should be preferred.

### 13.2 `cgo` calling convention

C strings are NUL-terminated; Go strings are length-prefixed and
can contain embedded NULs. `C.CString(goStr)` allocates a
NUL-terminated copy via `malloc`; the *caller* must
`C.free(unsafe.Pointer(cstr))` to avoid a heap leak. The footgun:
forgetting the `C.free` after `C.CString` leaks per call.

Passing a Go slice's backing array to C: the runtime pins memory
*during the cgo call*. After the call returns, the GC may relocate
the array. If the C code stashes the pointer, it becomes stale.
Defense: copy into C-allocated memory if the C side retains the
pointer.

### 13.3 `runtime.SetFinalizer` — finalizer surprises

Finalizers run on GC'd objects with caveats: order is
non-deterministic; finalizers may not run if no GC fires; a
finalizer referencing its own object resurrects it; cyclic
finalizers (two objects finalizing each other) never run. The Go
docs explicitly state finalizers are not a reliable cleanup
mechanism. Use `defer` and explicit `Close()` methods. Cross-link
to `firmware_embedded_security.md`.

---

## 14. `go.mod`, `go.sum`, module supply chain

### 14.1 `go install repo@latest` — bypasses go.sum verification

`go install path@version` installs and runs a binary from a remote
repository. The version specifier `@latest` resolves to the most
recent tag at install time. The resolution does *not* consult any
go.sum file from the user's environment (the install is typically
outside any module). The footgun: a typosquatted module path
returns an attacker-controlled binary that runs with the user's
privileges.

The module proxy (proxy.golang.org) caches successful resolutions
and provides a transparency log via sum.golang.org. The Go
toolchain verifies that the downloaded module's `go.sum` entry
matches the transparency log. But the *trust* in the transparency
log is conditional on the user verifying the published module
hash matches what they intended — which requires comparing the
hash to a known-good source.

Audit pattern: any `go install ...@latest` in CI or documentation
should be replaced with `go install ...@v1.2.3` (pinned version).

### 14.2 `replace` directives — silent dependency swaps

The `replace` directive in `go.mod` substitutes a different
module path or version for a dependency:

```go.mod
replace github.com/foo/bar => github.com/eve/evil v1.2.3
replace github.com/foo/bar => ../local/path
```

The replacement happens transparently at build time. A
malicious-looking `replace` directive in a transitive dependency
is *not* honored — only the main module's `go.mod` `replace`
directives apply to a build. This is a deliberate Go-module design
choice to prevent transitive `replace` attacks. But the main
module's own `replace` directives are powerful and unscrutinized
by default; any PR that adds a `replace` directive should be
reviewed for legitimacy.

### 14.3 Module proxy and the `GOSUMDB` checksum log

`proxy.golang.org` caches modules; `sum.golang.org` is the
transparency log that records `(module, version) -> hash`
mappings. The Go toolchain consults `sum.golang.org` (via
`GOSUMDB`) to verify that the hash of a downloaded module matches
the public log entry. The footgun: setting `GOSUMDB=off` disables
the check; `GOPRIVATE=*` disables both the proxy *and* the
checksum log for matching paths.

Audit pattern: `GOSUMDB=off` or `GONOSUMCHECK=*` in any CI
environment is a critical configuration bug.

### 14.4 The `go.sum` guarantee and its limits

`go.sum` records the hash of every module version used by the
build. When a module is added or upgraded, the toolchain fetches
the module *and* verifies the hash against the transparency log;
the resulting hash is recorded in `go.sum`. Subsequent builds
verify the downloaded module matches the recorded `go.sum` hash —
giving build-time integrity.

The guarantee: a CI build, given the same `go.mod` and `go.sum`,
will fail if any module's content has been tampered with. The
limits: the guarantee is build-time integrity, not source-time
integrity. If a malicious version is published *and* its hash is
recorded in the transparency log before any user fetches it, the
hash check passes; the build is "verified" but executes malicious
code. The defense is at the developer-review layer (pinning to
audited versions, reviewing `go.sum` diffs).

### 14.5 Vanity domains for module paths

Go module paths can use vanity domains (e.g., `go.uber.org/zap`)
that redirect via HTTP to the actual repository (typically
GitHub). The redirection is configured via `<meta>` tags in the
HTML response at the path. The footgun: if the vanity domain is
not under organizational control, an attacker who acquires it can
redirect `go get` to an attacker-controlled repository. The
defense is to use stable, organization-controlled vanity domains
or to use direct GitHub paths.

### 14.6 Reproducible-builds discipline

Russ Cox's multi-release effort made the Go toolchain itself
reproducible as of Go 1.21: given the same source, the same
toolchain produces byte-identical binaries. This closes the
trusted-builder gap in the supply chain — a build server's output
can be verified by any third party who re-runs the build. The
extended reproducibility story includes:

- Module content is canonicalized via the module proxy.
- The Go compiler is deterministic given the same input.
- Linker output is deterministic (modulo build IDs, which are
  controllable).
- Cross-compiled binaries are reproducible from the same source on
  any host.

Cross-link to `supply_chain_provenance_expertise.md` §"Reproducible
builds" and `cicd_supply_chain_expertise.md` §"Module ecosystems."

---

## 15. Web framework specifics

### 15.1 Gin: `c.Bind` / `c.ShouldBind` content-type sniffing

Gin's `c.Bind(&v)` and `c.ShouldBind(&v)` inspect the request's
`Content-Type` header to choose a decoder (JSON for
`application/json`, form for `application/x-www-form-urlencoded`,
multipart, XML, etc.). The footgun: an attacker controls the
Content-Type, and a form-encoded payload may parse differently
than the same payload sent as JSON — particularly for boolean,
integer, and array fields. The defense is to use the explicit
form: `c.BindJSON(&v)` if you mean JSON, `c.BindQuery(&v)` for
query params, `c.BindUri(&v)` for path params.

Gin also defaults to *not* failing on extra fields; the
`gin.EnsureBodyClosed` middleware and explicit
`json.Decoder.DisallowUnknownFields` are required for strict
parsing.

### 15.2 Echo: middleware ordering

Echo's middleware is registered in order; later registrations
wrap earlier ones. The footgun: authentication middleware
registered *after* a route-specific handler does not apply to that
handler. The defensive shape is to register security middleware
first, then routes, and to verify the registration order in tests.

### 15.3 chi: route-pattern semantics

chi uses a radix-tree router with `{param}` and `{param:regex}`
patterns. The footgun: the regex form allows arbitrary regex,
which can be a source of ReDoS if the pattern is complex.
Constraining patterns to simple forms (alphanumeric, integer,
UUID) and validating in the handler is the safer shape.

### 15.4 fiber: fasthttp underpinning

Fiber sits on top of `fasthttp`, which is a fork-of-`net/http`
implementation. fasthttp's request and response objects are *not*
goroutine-safe and are *reused* across requests via a pool. The
footgun: storing a reference to the request object (or any of its
fields, including headers and body) across goroutines, or after
the handler returns, accesses memory that has been recycled into
another request. The defense is to copy any needed data out of
the request before the handler returns or before spawning a
goroutine. The fiber documentation states this explicitly but it
is a frequent source of bugs.

Audit pattern: any `go func() { use(c) }()` inside a fiber handler
is a use-after-recycle candidate.

---

## 16. Detection patterns (Semgrep + govulncheck)

### 16.1 Semgrep patterns

A starter pattern library for Go-specific footguns:

```yaml
# Shell injection via exec.Command("sh", "-c", ...)
- pattern: exec.Command("sh", "-c", $X)
  message: "Shell command construction; verify $X is not user-controlled"

# math/rand in security context
- pattern: |
    import "math/rand"
    ...
    $TOKEN := rand.$F(...)
  message: "math/rand is not cryptographic; use crypto/rand"

# http.ListenAndServe without timeouts
- pattern: http.ListenAndServe($ADDR, $H)
  message: "http.ListenAndServe has no timeouts; use http.Server with timeouts"

# sync.Mutex value receivers
- pattern: |
    type $T struct {
      ...
      $M sync.Mutex
      ...
    }
    func ($R $T) $METHOD(...)
  message: "Value receiver on type containing sync.Mutex copies the mutex"

# Missing DisallowUnknownFields on json.Decoder
- pattern: |
    $D := json.NewDecoder($R)
    $D.Decode(&$V)
  message: "json.Decoder used without DisallowUnknownFields"

# unsafe.Pointer + uintptr round-trip
- pattern: |
    $U := uintptr(unsafe.Pointer($P))
    ...
    $Q := unsafe.Pointer($U)
  message: "uintptr held across statements; GC may move the object"

# InsecureSkipVerify in tls.Config
- pattern: |
    tls.Config{
      ...
      InsecureSkipVerify: true,
      ...
    }
  message: "InsecureSkipVerify disables certificate verification"

# Zip-Slip pattern (filepath.Join with archive entry name)
- pattern-either:
    - pattern: |
        for _, $F := range $R.File {
          ...
          $PATH := filepath.Join($BASE, $F.Name)
          ...
        }
  message: "Zip Slip candidate: validate archive entry path before extraction"

# Goroutine without context cancellation
- pattern: |
    go func() {
      for {
        $X := <-$CH
        ...
      }
    }()
  message: "Long-running goroutine without context cancellation"

# os.Setenv after init
- pattern: os.Setenv($K, $V)
  message: "os.Setenv may race with concurrent reads; prefer config struct"

# context.Background in request handler
- pattern: |
    func $H($W http.ResponseWriter, $R *http.Request) {
      ...
      $CTX := context.Background()
      ...
    }
  message: "Use r.Context() in HTTP handlers, not context.Background()"
```

Cross-link to the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the authoring
methodology (specs first, precision target ≥95% on a 10-repo
corpus).

### 16.2 `govulncheck` for known CVE coverage

`govulncheck` is the Google-maintained vulnerability scanner that
queries the curated database at `vuln.go.dev` and performs
call-graph reachability analysis to suppress findings that are
not actually reachable in the codebase. Run with:

```
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

The reachability analysis distinguishes between "imported"
(`govulncheck` reports it as informational) and "reachable"
(`govulncheck` reports it as actionable). The CI gate should fail
on reachable findings.

### 16.3 `staticcheck` / `golangci-lint` security cops

`staticcheck` is the de-facto static analyzer for Go; it ships
many security-relevant checks including SA1019 (deprecated APIs,
which includes `math/rand` in security contexts when migrated),
SA4006 (unused variable that may indicate a missed error), and
SA9003 (empty branch). `golangci-lint` aggregates `staticcheck`,
`gosec`, `errcheck`, `ineffassign`, and others into a single
runner with shared config.

The Trail of Bits Go-audit doctrine recommends the floor
configuration:

```yaml
linters:
  enable:
    - errcheck
    - gosec
    - govet
    - ineffassign
    - misspell
    - staticcheck
    - unused
```

`gosec` is the Go-specific security linter; it has rules for
crypto-misuse, hardcoded credentials, file-path mishandling, and
the integer-overflow and unsafe-pointer patterns. The rule corpus
is smaller than CodeQL or Semgrep but lower-friction to integrate.

Cross-link to the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview).

---

## 17. Defensive checklist and variant analysis

### 17.1 Twelve-item Go audit checklist

1. Search for `var err *T = nil` patterns and trace into interface
   returns; confirm no typed-nil-pointer leaks through the `error`
   interface.
2. Run `go vet ./...` and treat `copylocks` warnings as critical
   bugs.
3. Audit every struct embedding `sync.Mutex`, `sync.RWMutex`,
   `sync.WaitGroup`, `sync.Cond` for value-receiver methods.
4. Find every `for ... range` loop with `go func` or `defer` inside;
   verify the module is Go 1.22+ or that the loop variable is
   shadowed.
5. Audit every `defer f.Close()` inside a `for` loop; confirm the
   loop body has been extracted into a function for per-iteration
   defer scope.
6. Find every `exec.Command("sh", ...)` and `exec.Command("bash",
   ...)`; replace with direct binary invocation if user input is
   involved.
7. Find every archive-extraction loop (`zip`, `tar`); verify
   prefix-check on extracted paths and `Linkname` validation for
   tar.
8. Find every `http.ListenAndServe` and `http.Handler{}` with no
   timeouts; require explicit `ReadTimeout`, `WriteTimeout`,
   `IdleTimeout`, `MaxHeaderBytes`.
9. Find every `math/rand` import; verify no security-relevant
   token generation; replace with `crypto/rand`.
10. Find every `InsecureSkipVerify: true`; remove from production
    code paths.
11. Find every `os.Setenv` after `init`; assess concurrent-read
    risk.
12. Run `govulncheck ./...` and address every "reachable"
    finding.

### 17.2 Variant analysis

The variant-analysis discipline (cross-link
`vulnerability_research_methodology_expertise.md`) applies to Go
footguns in three ways:

- **Generics (Go 1.18+).** Type parameters add a new surface for
  `copylocks` blind spots, for type-erased operations that bypass
  the type system, and for accidental copies through generic
  functions that take `T` by value when `T` is a struct with an
  embedded mutex. Audit every generic function for value-parameter
  semantics.
- **Range-over-func iterators (Go 1.23+).** The new
  `range func` syntax allows custom iterators that yield values
  via a callback. The callback's signature determines whether
  early termination is possible (`yield(v)` returning false). The
  audit pattern is to verify every iterator handles early
  termination correctly and doesn't leak goroutines if the consumer
  stops iterating.
- **The `go-stratus-red-team` corpus.** The Datadog-published
  Stratus Red Team adversary-emulation framework includes Go-based
  attacks against cloud provider APIs. Reviewing the corpus
  surfaces patterns where Go libraries are used to drive
  privilege-escalation, credential-exfiltration, and lateral-
  movement chains. The corpus is a useful source for "what does a
  real attack against this Go API look like" examples.

### 17.3 Code review entry points

Cross-link to `code_review_expertise.md`. The click-count severity
heuristic applies directly: a `BinaryFormatter`-equivalent in Go
is `encoding/gob` unmarshaling untrusted data (gob also encodes
type information and can instantiate arbitrary registered types);
a `Path.Combine`-equivalent is `filepath.Join` without
prefix-check; a `Random()`-equivalent is `math/rand`; a
`HttpClient`-equivalent is `http.Client{}` with `InsecureSkipVerify`.

The audit pattern is the same: enumerate the language-specific
primitives in the bug class, identify their call sites, classify
each by reachability and trust boundary, then triage by severity.

---

## 18. References

### Go core team and design rationale
- Rob Pike — "Less is exponentially more": https://commandcenter.blogspot.com/2012/06/less-is-exponentially-more.html
- Rob Pike — "Concurrency is not parallelism": https://go.dev/blog/waza-talk
- Rob Pike — Wikipedia biography: https://en.wikipedia.org/wiki/Rob_Pike
- Robert Griesemer — Wikipedia biography: https://en.wikipedia.org/wiki/Robert_Griesemer
- Russ Cox — research!rsc blog: https://research.swtch.com/
- Russ Cox — "Reproducible, Verifiable, Verified Builds": https://research.swtch.com/vgo-repro
- Go 1.21 reproducible toolchain announcement: https://go.dev/blog/rebuild
- Russ Cox / Slashdot supply-chain interview: https://developers.slashdot.org/story/25/09/21/0650219/secure-software-supply-chains-urges-former-go-lead-russ-cox

### Go cryptography and Geomys
- Filippo Valsorda — words.filippo.io: https://words.filippo.io/
- Geomys — Geomys.org: https://geomys.org/
- Filippo Valsorda — Geomys Standard of Care: https://words.filippo.io/standard-of-care/
- Filippo Valsorda — age encryption tool: https://github.com/FiloSottile/age
- Geomys blueprint announcement: https://words.filippo.io/geomys/

### Race detection and fuzzing
- Dmitry Vyukov — Google profile: https://www.linkedin.com/in/dvyukov/
- Google Testing Blog — ThreadSanitizer: https://testing.googleblog.com/2014/06/threadsanitizer-slaughtering-data-races.html
- Dmitry Vyukov — syzkaller Linux Security Summit 2018: https://events19.linuxfoundation.org/wp-content/uploads/2017/11/Syzbot-and-the-Tale-of-Thousand-Kernel-Bugs-Dmitry-Vyukov-Google.pdf
- ThreadSanitizer C++ manual: https://github.com/google/sanitizers/wiki/threadsanitizercppmanual

### Go vulnerability management
- Govulncheck announcement (Sept 2022): https://go.dev/blog/vuln
- Govulncheck v1.0.0 (July 2023): https://go.dev/blog/govulncheck
- Go vulnerability documentation: https://go.dev/doc/security/vuln/
- Go security page: https://go.dev/doc/security/

### nil interfaces and error handling
- Dave Cheney — "Typed nils in Go 2": https://dave.cheney.net/2017/08/09/typed-nils-in-go-2
- DoltHub — "Much Ado About Nil Things": https://www.dolthub.com/blog/2023-09-08-much-ado-about-nil-things/
- Go proposal #30294 — explicit nil-receiver cast: https://github.com/golang/go/issues/30294

### Concurrency and channels
- Tony Bai / Eli Bendersky — "Beware of copying mutexes in Go": https://eli.thegreenplace.net/2018/beware-of-copying-mutexes-in-go/
- Ardan Labs — "Goroutine Leaks: The Forgotten Sender": https://www.ardanlabs.com/blog/2018/11/goroutine-leaks-the-forgotten-sender.html
- Go 1.26 goroutine-leak profile: https://dev.to/gabrielanhaia/goroutine-leaks-in-go-the-4-patterns-and-the-new-profile-in-go-126-5e73
- antonz.org — "Detecting goroutine leaks": https://antonz.org/detecting-goroutine-leaks/
- Go vet copylocks discussion: https://github.com/golang/go/issues/13675

### Loop-variable semantics
- Go 1.22 loop-variable announcement: https://go.dev/blog/loopvar-preview
- Go101 — "for Loop Semantic Changes in Go 1.22": https://go101.org/blog/2024-03-01-for-loop-semantic-changes-in-go-1.22.html
- Go wiki — LoopvarExperiment: https://go.dev/wiki/LoopvarExperiment
- Proposal #60078 — less error-prone loop variable scoping: https://github.com/golang/go/issues/60078

### Slices and aliasing
- Redowan Delowar — Go slice gotchas: https://rednafi.com/go/slice-gotchas/
- Blog Title — Go slices gotchas: https://blogtitle.github.io/go-slices-gotchas/
- Go wiki — SliceTricks: https://go.dev/wiki/SliceTricks

### HTTP and routing
- Go 1.22 routing enhancements: https://go.dev/blog/routing-enhancements
- Eli Bendersky — "Better HTTP server routing in Go 1.22": https://eli.thegreenplace.net/2023/better-http-server-routing-in-go-122/
- net/http enhanced ServeMux discussion: https://github.com/golang/go/discussions/60227

### JSON
- encoding/json documentation: https://pkg.go.dev/encoding/json
- Proposal #15314 — Decoder reject unknown fields: https://github.com/golang/go/issues/15314

### Zip Slip and Tar Slip
- Snyk Zip Slip disclosure (2018): https://security.snyk.io/research/zip-slip-vulnerability
- mholt/archiver CVE-2025-3445: https://research.jfrog.com/vulnerabilities/archiver-zip-slip/
- HashiCorp go-slug HCSEC-2025-01: https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719

### Trail of Bits Go corpus
- Trail of Bits — "Security assessment techniques for Go projects": https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/
- Trail of Bits Testing Handbook: https://appsec.guide/
- Trail of Bits — fuzzing category: https://blog.trailofbits.com/categories/fuzzing/

### Kris Nóva
- Kris Nóva biography: https://krisnova.net/bio/
- Nivenly Foundation: https://nivenly.com/

### Cross-cutting Go security
- Go security best practices: https://go.dev/doc/security/best-practices
- Go vulnerability database: https://vuln.go.dev/
- gosec security linter: https://github.com/securego/gosec
- staticcheck: https://staticcheck.dev/
- golangci-lint: https://golangci-lint.run/
