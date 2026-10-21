# Rust Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Rust language team designers, Rust compiler engineers, the academic Rust operational-semantics community, and the institutional advisories that catalog Rust-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — cataloguing primitives whose
> *default behavior* in a specific language ecosystem is unsafe, distinct from
> cross-language bug-class docs (deserialization, cryptography, race conditions,
> CI/CD supply chain) that cover attack surface by class rather than by language.
> The 2024-2026 load-bearing updates: Tree Borrows won a PLDI'25 distinguished
> paper award and ships in MIRI as an opt-in alternative to Stacked Borrows
> (still the default); the `static_mut_refs` lint became deny-by-default in the Rust 2024
> edition, targeting one of the oldest unsoundness footguns; the Rust Project's
> Safe Transmute initiative (Project Safe Transmute, RFC 2835) progressed to an
> experimental compiler-supported analysis; the `zerocopy` and `bytemuck`
> ecosystems now provide first-class derive-macro-based safe transmutation;
> `cargo-audit` 0.17.3+ performs binary auditing via `cargo auditable`
> embedded SBOM metadata; the supply-chain surface continued to be exercised
> by `build.rs` install-time code execution incidents and the `tar`-crate
> extraction-permissions flaw in Cargo, CVE-2026-33056. The behavioral footgun surface in Rust differs structurally
> from the dynamic-language footgun surface: Rust footguns are concentrated in
> the **`unsafe` keyword**, in the **soundness contract** between safe and
> unsafe code, and in **runtime-only failure modes** (panic, overflow,
> deadlock, cancellation) that the compiler cannot fully prevent.
>
> **Researchers:**
> - **Aria Beingessner** (Gankra / Aria Desires) — formerly Mozilla Research,
>   subsequently Apple Swift team; designed Rust's standard collection APIs and
>   `Vec` / `HashMap` internals; authored *TURPL: The Unsafe Rust Programming
>   Language* (the canonical predecessor of the Rustonomicon) during her
>   internship at Mozilla; the long-running essay corpus at faultlore.com
>   documents the practical reality of writing sound `unsafe` Rust
> - **Ralf Jung** — PhD at MPI-SWS, now assistant professor at ETH Zürich
>   Programming Language Foundations Lab; PhD thesis "Understanding and
>   Evolving the Rust Programming Language" (2020); designed and proved
>   Stacked Borrows (POPL 2020) and Tree Borrows (PLDI 2025) as operational
>   aliasing models for Rust; his group develops MIRI (the Rust UB
>   interpreter); first author of the POPL 2026 paper "Miri: Practical Undefined Behavior Detection for
>   Rust"; the canonical academic source for what Rust's unsafe semantics
>   actually mean
> - **Niko Matsakis** — Senior Principal Engineer at AWS; co-lead of the Rust
>   language design team; PhD in programming languages from ETH Zürich (2011);
>   led the design of the Rust borrow checker (the language's central
>   soundness primitive); Project
>   Director at the Rust Foundation (appointed October 2025); the long-running
>   essay corpus at smallcultfollowing.com documents the borrow-checker
>   design rationale and the Polonius rewrite
> - **Felix Klock II** (pnkfelix) — Principal Software Engineer at AWS (formerly
>   Mozilla Research); Rust Compiler Team Maintainer; PhD in programming
>   languages from Northeastern University; primary contributor to the Rust
>   compiler's borrow-checker implementation, NLL (non-lexical lifetimes),
>   and the dropck (drop-check) discipline
> - **Steve Klabnik** — formerly Mozilla and Rust core team; co-author of
>   *The Rust Programming Language* (3rd edition with Carol Nichols and Chris
>   Krycho, No Starch Press); led the Rust documentation team for years;
>   primary author of the official Rust Book including Chapter 20 on
>   unsafe Rust; the institutional voice for "how Rust is taught"
> - **Manish Goregaokar** (Manishearth) — Rust Project team member; leads
>   the Clippy team, Devtools team, Rustfmt contributors,
>   and Website team; formerly Mozilla Research engineer on Servo; primary
>   contributor to ICU4X (Unicode Consortium internationalization in Rust);
>   the corpus at manishearth.github.io is one of the longest-running
>   technical-writing voices on Rust language design and Servo
>   memory-safety engineering
> - **Jane Lusby** (yaahc) — Error Handling Project Group Lead; Project
>   Director of Collaboration at the Rust Foundation; author of the `eyre`
>   crate (a fork of `anyhow` with customized error reports); presenter of
>   the canonical RustConf 2020 talk "Error handling Isn't All About Errors"
>   that introduced the "error report vs. error context" framing that shaped
>   modern Rust error-handling discipline; co-author of RFC 2965 (Project
>   Error Handling)
> - **Trail of Bits** (institutional) — security research firm; corpus on
>   Rust-specific audit tooling, the `dylint` framework for custom Clippy
>   lints, the `cargo-geiger` integration for unsafe-code counting in
>   dependency trees; multi-year Rust-codebase audit experience covering
>   blockchain consensus (Solana, Polkadot ecosystems), zero-knowledge
>   tooling, and high-assurance Rust deployments
> - **RustSec advisory database team** (institutional) — operated by the
>   Rust Secure Code Working Group; maintains the canonical
>   `rustsec/advisory-db` repository and the `cargo-audit` toolchain;
>   primary upstream for vulnerability data exported to OSV, GHSA, and
>   downstream supply-chain auditing tools; the institutional voice for
>   what counts as a "Rust security advisory" and what counts as a
>   "memory-corruption-classed soundness bug"
> - **Yoshua Wuyts** (yoshuawuyts) — Rust async working group; co-author of
>   the async traits work and the `pin-project` design literature; long
>   essay corpus at blog.yoshuawuyts.com on Pin projections, the
>   self-referential-future failure mode, and the cancellation-safety
>   discipline; co-designed several of the canonical async-trait
>   stabilization paths
> - **without.boats** (boats / Saoirse Shipwreckt) — formerly
>   Rust language team async working group; the blog at without.boats has
>   been the primary technical voice on Pin's design rationale, the
>   "Pin is not unsafe" framing, and the async cancellation problem;
>   long-running argument for why Rust's `Pin<P>` ended up the shape it did
> - **Carl Lerche** — Tokio creator; primary maintainer of the canonical
>   Rust async runtime; long essay corpus on cancellation safety,
>   `tokio::select!` failure modes, and the cooperative-scheduling
>   discipline that async Rust requires
>
> **Institutional contributors:** Rust Project (`rust-lang/rust`, `cargo`,
> `clippy`, `miri`, `rustfmt`, `rust-analyzer`); Rust Secure Code Working
> Group (`rustsec/advisory-db`, `cargo-audit`, the `RUSTSEC-YYYY-NNNN`
> advisory ID scheme); Rust Foundation (governance + funding); the academic
> Iris-project (Coq mechanization of Rust semantics: Stacked Borrows, Tree
> Borrows, RustBelt); Trail of Bits + NCC Group + Doyensec + Veracode (the
> institutional Rust audit corpus); the Rust Async Working Group (Tokio,
> async-std, smol, the `Pin` and `async fn` stabilization design); MITRE
> CWE (CWE-416, CWE-415, CWE-119, CWE-787, CWE-362, CWE-787); Project Safe
> Transmute (RFC 2835 + 2024-2026 stabilization track).
>
> **What this doc is NOT:** not a Rust language tutorial, not a replacement
> for cross-language bug-class guidance, not a substitute for Clippy or
> MIRI. It is the Rust-specific layer beneath cross-language audit
> heuristics. Read this before reviewing any non-trivial Rust codebase that
> contains `unsafe` blocks, FFI, async, or shared mutable state; read
> `code_review_expertise.md` for the click-count severity heuristic that
> lifts each footgun into a triage decision.

Cross-links: `race_conditions_concurrency_expertise.md` for the cross-language
concurrency / data-race / TOCTOU surface (Rust's `std::sync::Mutex` poisoning
and async cancellation race classes are the Rust incarnation);
`firmware_embedded_security.md` for the low-level interop / register-mapping /
memory-mapped-IO surface that drives much real-world `unsafe` Rust;
`deserialization_expertise.md` for the cross-language deserialization bug
class (serde + bincode + RON + ron-rs are the Rust incarnations);
`cicd_supply_chain_expertise.md` for the cross-language registry-and-build
attack class (crates.io + `build.rs` + `cargo install` are the Rust
incarnations); `code_review_expertise.md` for the candidate-point auditing
methodology and click-count severity heuristic;
`semgrep_rule_authoring.md` for detection-rule authoring guidance;
`fuzzing_discipline_expertise.md` for the `cargo-fuzz` + `libfuzzer` +
`afl.rs` discipline; `cryptography_expertise.md` for the `ring` / `rustls` /
`RustCrypto` ecosystem cross-cuts.

---

## 1. The behavioral-footgun framing

### 1.1 Rust's "safe by default, unsafe by opt-in" model

Rust draws an explicit boundary between **safe Rust** (compiler proves
no undefined behavior, modulo compiler/std bugs) and **unsafe Rust**
(opts out of specific checks; the programmer upholds the invariants).
The `unsafe` keyword is the single, grep-able opt-out marker; every
Rust audit begins with `rg '\bunsafe\b'`.

Rust footguns are concentrated in:

1. The **`unsafe` blocks** and the contract they expose.
2. The **boundary between safe and unsafe** — safe code can trigger
   UB if the unsafe contract is wrong.
3. **Runtime-only failure modes** the type system cannot rule out:
   panics, integer overflow, deadlocks, async cancellation, leaks.
4. **Supply-chain surface** that bypasses the type system entirely:
   `build.rs`, procedural macros, `cargo install`.

Every footgun in this document satisfies: **the compiler accepts the
code without warning**, **the standard library exposes a primitive
whose default semantics are unsafe in adversarial input**, or **a
near-mandatory crate is the de-facto incarnation of a bug class**.
Pure `unsafe`-block-internal UB is covered by the Rustonomicon; this
doc covers the less-obvious failure modes production codebases exhibit.

### 1.2 The soundness boundary

The load-bearing concept for auditing Rust is the **soundness boundary**.
A function or `unsafe` block is **sound** if, for every input satisfying
its documented preconditions, it does not exhibit UB. Safe Rust is sound
by construction; unsafe Rust is sound only if proven by its author.

Critical asymmetry: **if a safe API can cause UB via valid safe Rust
input, the unsafe-block author is at fault — not the caller**. This is
Gankra's canonical argument. When `SmallVec::grow` exhibited a
double-free (RUSTSEC-2019-0009), the bug was the `unsafe` block's, not
the caller's. The contract the `unsafe` block exposed was unsound;
the fix landed in the `unsafe` block.

Rust audits cluster around `unsafe` blocks even when the *triggering*
path is safe. Every public-API function on a type containing `unsafe`
is a candidate point for "find safe-input that causes UB." Cross-link
`code_review_expertise.md` § candidate-point auditing.

### 1.3 What the borrow checker cannot prove

The borrow checker proves *memory safety* (no use-after-free, no
double-free, no data race) within safe Rust. It does *not* prove:

- **Logical correctness** — `if user.is_admin()` can be wrong, the
  compiler does not know.
- **Absence of panics** — `arr[idx]` compiles regardless of whether `idx`
  is in-bounds; the bounds check happens at runtime.
- **Absence of deadlocks** — `Mutex::lock` returns a guard; nothing
  prevents you from locking two mutexes in opposite orders in two
  threads.
- **Absence of integer overflow in release builds** — debug builds panic,
  release builds wrap silently (cross-link § 10).
- **Absence of leaks** — `mem::forget`, `Box::leak`, `Rc` cycles, and
  detached threads can all leak unboundedly; "no leaks" is not a Rust
  soundness invariant.
- **Behavior of `unsafe` blocks** — the borrow checker disables itself
  inside `unsafe { }` for the operations the keyword authorizes; the
  programmer is the proof obligation.
- **Behavior across FFI boundaries** — `extern "C"` functions are treated
  as black boxes; the compiler trusts the signature.
- **Cancellation safety in async code** — dropping a future at an
  `.await` point can leave state half-mutated; the compiler does not
  warn (cross-link § 7).

Every footgun in this document falls into one of these gaps.

### 1.4 The audit-cost asymmetry and detection discipline

The developer writes `unsafe { std::mem::transmute(x) }` once; the
auditor reads it many times and must verify size + alignment + layout
+ provenance + initialization + lifetime each time. Detection tooling
— `cargo-audit`, `clippy::pedantic`, `MIRI`, `cargo-geiger`, `semgrep`
— is the only scalable answer. Read this doc as *what to teach the
tool to find*, not as one-at-a-time mistakes.

---

## 2. `unsafe` blocks — the explicit escape hatch

### 2.1 The five things `unsafe` authorizes

The Rust Book (Chapter 20) enumerates the *five specific things* an
`unsafe` block lets you do that safe Rust does not:

1. **Dereference a raw pointer** (`*ptr` where `ptr: *const T` or
   `*mut T`).
2. **Call an unsafe function or method** (one declared `unsafe fn` or
   imported as `extern "C"` etc.).
3. **Access or modify a mutable static variable** (`static mut FOO: T`).
4. **Implement an unsafe trait** (one declared `unsafe trait`).
5. **Access a field of a `union`** (unions are not type-tagged; reading
   a field is a re-interpretation of the bytes).

Everything else that safe Rust allows is also allowed inside `unsafe`. An
`unsafe` block does **not** "turn off the borrow checker for everything";
it specifically authorizes these five operations and leaves the rest of
the type system intact. The common misunderstanding ("I'll wrap my whole
function in `unsafe` to silence the compiler") is wrong: the borrow
checker still runs, mutability is still enforced, lifetimes are still
checked.

### 2.2 `unsafe fn` vs `unsafe { }` — different semantics

Two related but distinct keywords:

- **`unsafe fn foo()`** — *calling* `foo` requires upholding `foo`'s
  preconditions. The caller is on the hook for the safety contract.
- **`unsafe { ... }`** — authorizes the five operations inside its
  scope. The block author is on the hook for soundness.

Calling `unsafe fn foo()` from safe code requires wrapping in `unsafe {
foo() }`. The wrap is a programmer-visible affirmation: "I read foo's
safety contract and my arguments satisfy it."

Rust 2024 added **`unsafe(...)` attribute syntax**: `#[unsafe(no_mangle)]`
and `#[unsafe(link_section = "...")]` require explicit `unsafe()` for
attributes whose effect creates safety obligations.

### 2.3 The soundness boundary in practice

The hard rule from the Rustonomicon, Unsafe Code Guidelines, and
Gankra's TURPL: **if a safe public API can cause UB via valid safe
Rust input, the bug is in the `unsafe` block**. Audit must trace the
full surface of the public safe API and ask "can any sequence of safe
calls produce input that the `unsafe` block does not handle?"

Historical example: `mem::uninitialized<T>()` was a *safe* function
that produced UB for most `T` (since uninitialized bit patterns are
invalid for `bool`, `&T`, `NonZeroU32`, enums, etc.). Deprecated in
Rust 1.39 for `MaybeUninit<T>` (§ 5).

### 2.4 "You can't 'just' use the unsafe escape hatch"

Pop mythology: "drop down to `unsafe` when the borrow checker is
wrong." The counter:
**`unsafe` does not give you C semantics**. It authorizes specifically
the five operations under the constraint that all other Rust
invariants (provenance, aliasing, validity, layout) still hold.

Examples of UB *despite* `unsafe`:

- Two `&mut T` to the same memory (Stacked / Tree Borrows violation)
  — even when constructed via raw-pointer cast.
- Reading uninitialized memory as `bool` even with correct alignment.
- `transmute<u32, NonZeroU32>(0)` — niche-optimization invariant.

Auditor takeaway: evaluate `unsafe` blocks against the full Rust
memory model, not C-style "did the pointer arithmetic check out."

### 2.5 Real RustSec advisory corpus — patterns

The RustSec database (rustsec.org) catalogs real Rust unsoundness:

- **`smallvec` RUSTSEC-2019-0009** — double-free / use-after-free in
  `SmallVec::grow()` when `new_cap == cap`. Safe API exposed UB.
- **`smallvec` RUSTSEC-2019-0012** — memory corruption in
  `SmallVec::grow` when `new_cap < cap`; attacker-controlled value
  could corrupt allocator metadata.
- **`actix-web` RUSTSEC-2018-0019** — three classes simultaneously:
  unsoundly coerced `&T` to `&mut T`, extended `&str` lifetimes, added
  `Send` to non-`Send` types.
- **`ordnung::compact::Vec` RUSTSEC-2020-0038** — soundness issues
  similar to smallvec.

**Pattern:** most common Rust soundness bug is "author re-implemented
a faster `Vec` / `HashMap` / `Box` and got an unsafe invariant wrong."
Audit heuristic: crates named "compact" / "small" / "no_std-vec"
have elevated soundness priors.

### 2.6 `cargo-geiger` — counting unsafe in dependencies

`cargo-geiger` reports `unsafe` block / fn / trait / impl counts per
crate in the dependency tree. Heuristic: `unsafe` budget should match
the crate's purpose. A TLS or SIMD crate has legitimate reasons; a
"JSON pretty printer" with many `unsafe` blocks is suspicious.

---

## 3. `transmute` and type punning

### 3.1 `std::mem::transmute<T, U>` — the type-system bypass

`std::mem::transmute<T, U>(x: T) -> U` reinterprets the bits of `x`
as a value of type `U`. The function is `unsafe` and has two
requirements (only the size check is enforced at compile time):

- `size_of::<T>() == size_of::<U>()`.
- The transmutation must not produce a value with an invalid bit pattern
  for `U` (e.g., a `bool` that is neither 0 nor 1, a `char` outside the
  Unicode scalar range, a `&T` that does not point to a valid `T`, a
  `NonZeroU32` containing 0).

The std-lib documentation warns: "This makes `transmute` incredibly
unsafe. `transmute` should be the absolute last resort." The
laundry list of UB classes it can produce: pointer-int casts violating
provenance, lifetime extension creating dangling references, alignment
violations on later access, layout mismatches between two structs that
*look* identical but are not `#[repr(C)]`.

### 3.2 Reference transmutation — the lifetime trap

The common `transmute` audit hazard is **lifetime extension**:

```rust
fn extend_lifetime<'a, T>(r: &'a T) -> &'static T {
    unsafe { std::mem::transmute(r) }
}
```

This compiles and returns `&'static T`, but the underlying storage is
still tied to `'a`. Once the original storage is freed, the "static"
reference dangles; subsequent use is UB.

Modern alternatives: `OnceCell` / `OnceLock` for lazy statics;
`Box::leak(Box::new(x))` for real `&'static mut T`; `Cow<'static, T>`
or `Arc<T>` for shared ownership.

### 3.3 Safer alternatives — `from_bits` and friends

Most legitimate `transmute` use is numeric bit-pattern reinterpretation;
the std-lib has safe alternatives:

- **`f64::to_bits` / `f64::from_bits`** — round-trip `f64`↔`u64`.
- **`u32::to_be_bytes` / `u32::from_be_bytes`** — endian-explicit.
- **`char::from_u32` / `char::from_u32_unchecked`** — checked vs unchecked.

For struct / array type-punning, use `bytemuck` or `zerocopy`.

### 3.4 `bytemuck` and `zerocopy` — safe transmutation

- **`bytemuck`** — marker traits `Pod`, `Zeroable`, `NoUninit`,
  `AnyBitPattern`, `CheckedBitPattern`. Each is `unsafe` to implement;
  derive macros restrict to verifiable layouts. `bytemuck::cast<T, U>`
  requires both types implement the appropriate markers.
- **`zerocopy`** — `FromBytes`, `IntoBytes`, `Unaligned` plus six
  `transmute!` macros with compile-time size + alignment checks.

Both crates' marker traits remain `unsafe` to implement — the "this is
POD" assertion is the programmer's — but safe transmute functions are
guarded at the type-system level.

Project Safe Transmute (RFC 2835) brings this into the compiler; as of
2026 it remains experimental.

### 3.5 Cross-link to firmware / embedded interop

Embedded Rust transmutes between MMIO register structs, packet buffers,
protocol frames. `#[repr(C)]` and `#[repr(packed)]` are load-bearing:
without them the compiler may reorder fields. `transmute` between
non-`#[repr(C)]` structs is UB even if field types match. Cross-link
`firmware_embedded_security.md` § MMIO discipline.

---

## 4. Lifetime escape via `Box::leak`, `mem::forget`, `ManuallyDrop`

### 4.1 `Box::leak` — heap to `&'static mut T`

`Box::leak(b: Box<T>) -> &'static mut T` consumes the `Box`, returns a
`&'static mut T`, and **never frees** the allocation. Permanent leak.

Legitimate: `'static` config at startup, FFI handoff to host. Footgun:
using `Box::leak` to "fix" borrow-checker errors causes memory
exhaustion if run in a loop; leaking values that hold external
resources (file handles, sockets, mutex guards, task handles) keeps
the resource forever.

### 4.2 `mem::forget(x)` — explicit `Drop` suppression

`mem::forget(x)` takes ownership and discards `x` without running
`Drop`. **Safe** (no `unsafe` keyword) — leaking is not UB per the
Rustonomicon's "Leaking" chapter.

Correct use: FFI ownership transfer (`Box<T>` handed to C, which calls
its own free; Rust must not run `Drop`). Reconstruct on return via
`Box::from_raw`. Incorrect use: any "I want to skip `Drop` for a value
that holds an external resource" — compiles silently, resource leaks.

### 4.3 `ManuallyDrop<T>` — same effect, explicit

`ManuallyDrop<T>` wraps a value with a no-op `Drop`. Modern replacement
for `mem::forget`: explicit at the type level, composable via
`ManuallyDrop::take` and `ManuallyDrop::drop`, required for union
fields with destructors.

Audit: `mem::forget` calls are rare and should be clearly documented
(near FFI). `ManuallyDrop` should pair with explicit `drop` / `take`
or a documented FFI handoff.

### 4.4 The "RAII guarantee that doesn't"

`Drop` runs at end-of-scope, *except*:

- **`mem::forget`** / **`Box::leak`** / **`ManuallyDrop`** — explicit.
- **`Rc<T>` / `Arc<T>` cycles** — neither refcount reaches zero.
- **Detached `JoinHandle`** — dropping detaches; resources leak.
- **Panic-during-Drop while unwinding** — aborts process (§ 9).
- **`std::process::exit`** — terminates without running `Drop`.

RAII guarantee: in the absence of explicit suppression, `Drop` runs on
stack unwind. Not "resources will always be released."

### 4.5 Security-relevant leaks

Resources whose leak is a security concern:

- **File descriptors / sockets** — eventually `EMFILE`; DoS if
  attacker triggers the leak path.
- **Cryptographic key material** — `Vec<u8>` keys not zeroed on leak.
  Use `zeroize::Zeroizing<T>` (cross-link `cryptography_expertise.md`)
  and ensure `Drop` actually runs.
- **Mutex guards** — leaked guard = permanently-held mutex = deadlock.
- **Async task handles** — leaked handle detaches the task; outlives
  request context.

Heuristic: every `mem::forget`, `Box::leak`, `ManuallyDrop::new`
warrants a comment explaining why `Drop` is suppressed. Absence is an
audit finding.

---

## 5. `MaybeUninit<T>` and uninitialized memory

### 5.1 The pre-1.36 `mem::uninitialized<T>()` — "one of the worst mistakes"

Pre-Rust-1.36, `mem::uninitialized<T>()` was a *safe* function returning
an uninitialized `T`. The `uninit` crate's documentation calls it one of
the worst mistakes of the language — for most `T`, an
uninitialized bit pattern is *not* a valid `T` (`bool` must be 0/1;
`&T` must point at a valid `T`; `NonZeroU32` must not be 0; enums
require valid discriminants). Mere existence of such a value is UB.

Deprecated Rust 1.39. Replacement: `MaybeUninit<T>`.

### 5.2 `MaybeUninit<T>::uninit()` — explicitly uninitialized

`MaybeUninit<T>` is a wrapper representing *possibly* uninitialized
data. `MaybeUninit::<T>::uninit()` returns a value whose memory is
uninitialized but whose type allows arbitrary bit patterns.
`assume_init(self) -> T` is `unsafe`: the caller promises the bytes
form a valid `T`.

### 5.3 `assume_init()` — the promise, the UB

`assume_init` on partially-initialized memory is **immediate UB**, even
if the result is unused. Every byte must be initialized; every type-
level invariant (enum discriminant, `NonZeroU32` non-zero, UTF-8 for
`String`) must hold.

The C-style intuition "uninit `u8` is just some byte" is wrong. The
Rust abstract machine treats uninitialized bytes as a poison state;
observing them is UB even for primitive types.

### 5.4 Partial initialization — drop-guard pattern

Common idiom for an uninit `[T; N]`:

```rust
let mut arr: [MaybeUninit<T>; N] = MaybeUninit::uninit_array();
for i in 0..N {
    arr[i].write(compute_element(i));
}
let arr: [T; N] = unsafe { MaybeUninit::array_assume_init(arr) };
```

Footgun: if the loop panics partway, written elements leak (for `T:
Drop`, silent resource leakage). Fix: drop-guard tracking write count
that runs `Drop` on already-written elements on non-normal drop.

### 5.5 Soundness CVEs

The `zerocopy` crate's CVE history includes multiple `MaybeUninit`-
adjacent issues. Common pattern: "allocated buffer, passed to C, C
wrote some bytes, promoted to `&[u8]` without verifying actual byte
count." Fix is always "verify the precondition before `assume_init`."

Audit heuristic: every `assume_init` call should have an adjacent
comment justifying full initialization, referencing the writer (loop,
FFI call, `copy_nonoverlapping`) and any return-value check that
established the write completed.

---

## 6. `Pin` / `Unpin` invariants

### 6.1 `Pin<P>` — the address-stability primitive

`Pin<P>` (where `P` is `&mut T`, `Box<T>`, `Arc<T>`, etc.) wraps a
pointer and promises **the pointee will not be moved** between Pin
creation and pointee drop.

Motivation: address-sensitive types contain pointers back into
themselves. The canonical case: async state machines with references
spanning `await` points. Moving the outer struct invalidates internal
pointers. Rust generally allows free moves; `Pin` is the type-level
promise that the value will not move.

### 6.2 `Unpin` — most types are exempt

`Unpin` is an auto trait. Types not requiring address stability
implement `Unpin` automatically; for them, `Pin<&mut T>` is effectively
`&mut T` (`Pin::into_inner` and `Pin::get_mut` are free).

Types *not* `Unpin`:

- **`PhantomPinned`** marker — explicit opt-out.
- **Compiler-generated async state machines** — futures may contain
  self-references at `await` points.
- **Manual self-referential structs** with `_pin: PhantomPinned`.

The discipline only bites for async-fn-generated futures.

### 6.3 The Pin projection problem

"Projecting" a `Pin<&mut Outer>` to a field requires deciding whether
the field is *structurally pinned* (also address-stable; project as
`Pin<&mut Inner>`) or not (project as `&mut Inner`). The choice must
be consistent across the impl: structural-pinning requires `Outer:
!Unpin` unless `Inner: Unpin`.

`pin-project` and `pin-project-lite` use procedural macros to generate
correct projections from an `#[pin]` field marker, enforcing
consistency at compile time.

### 6.4 Manually projecting `Pin` via `unsafe` — the footgun

```rust
fn project_inner(self: Pin<&mut Outer>) -> Pin<&mut Inner> {
    unsafe { self.map_unchecked_mut(|outer| &mut outer.inner) }
}
```

`map_unchecked_mut` requires "the inner pointee will not be moved out
of." If another method on `Outer` calls `Pin::into_inner` (because
`Outer: Unpin`), this assumption is violated.

Audit checklist for `map_unchecked_mut`:

1. `Outer: !Unpin` (or inner field is also `Unpin`).
2. No other method moves the inner field (`mem::replace`, `mem::swap`).
3. `Drop` impl does not move the inner field before dropping.

`pin-project` enforces these via the type system; manual projection
must reproduce by hand.

### 6.5 Cross-link to async

Almost all `Pin` usage in Rust is in async contexts; the runtime's
`poll` takes `Pin<&mut Self>`. Cross-link § 7.

---

## 7. Async cancellation safety

### 7.1 `tokio::select!` — branches cancel each other

`tokio::select!` races futures; the first to complete wins and the
others are **dropped** without completing. The classic pitfall:

```rust
loop {
    tokio::select! {
        msg = stream.next() => { process(msg); }
        _ = shutdown.recv() => { break; }
    }
}
```

If `shutdown.recv()` wins the race after `stream.next()` has already
read a message into its internal buffer but before yielding it, the
message is lost.

### 7.2 Cancellation safety — the contract

A future is **cancellation-safe** if dropping it at any `.await` leaves
the world in a state where it can be re-created and retried, with no
lost work or half-completed mutations.

The tokio docs are explicit: `Receiver::recv` (mpsc) and
`tokio::time::sleep` are cancel-safe. `AsyncBufReadExt::read_line` is
not (may consume bytes from the underlying reader). `Mutex::lock` is
not (losing your place in the queue can starve).

**You cannot tell cancellation safety from a signature.** The property
is documented in prose or not at all. Audit burden: read every
`tokio::select!` and verify each branch.

### 7.3 The drop-in-the-middle-of-await lifecycle

When a future is dropped at `.await`: locals at the await point have
destructors run; owned resources are released *from the Rust side*.

The remote system may have already received bytes, opened a
transaction, or sent partial output. Cancellation safety in Rust is
*local* (the Rust process leaves no inconsistent state), not
*distributed*. Distributed systems require application-level
reconciliation (idempotency keys, transactional outboxes).

### 7.4 `tokio::spawn` + `JoinHandle`

`tokio::spawn(future)` returns `JoinHandle<Output>`:

- **Dropping the handle** does *not* cancel; the task detaches and
  continues. Result is discarded.
- **`JoinHandle::abort()`** signals cancellation at the next await.
- **Awaiting the handle** returns `Result<Output, JoinError>`.

Footgun: detached tasks survive scope. "Per-request `tokio::spawn`"
patterns can leak handlers that outlive their request context. Audit:
every `tokio::spawn` needs an explicit handle lifecycle.

### 7.5 Async traits + `Send` bounds

Native async traits (stable Rust 1.75) produce futures whose `Send`-
ness depends on captured types. `dyn Trait + Send` requires every
local captured across `.await` to be `Send`. Error messages point at
the trait bound, not the actual capture.

`std::sync::Mutex` guards are typically not `Send` and shouldn't be
held across `.await` anyway (deadlock anti-pattern). Cross-link
`code_review_expertise.md` § auth-homogeneity: heterogeneous `Send`-
ness in a trait object is suspicious; lift to the trait definition.

### 7.6 Async-Drop — unstable

`AsyncDrop` remains nightly-only as of 2026. Resources
needing async cleanup (DB connection close RPC, WebSocket close frame,
async buffer flush) **cannot be cleanly released via RAII** on stable
Rust. Workaround: explicit `async fn close(&mut self)` plus a
synchronous `Drop` that panics in debug if `close` wasn't called.
Rust's "`Closeable` problem"; cross-link `java_footguns_expertise.md`.

---

## 8. `Arc<Mutex<T>>` deadlocks + sync primitive footguns

### 8.1 The classic two-mutex deadlock

```rust
fn thread_a(m1: &Mutex<()>, m2: &Mutex<()>) {
    let _g1 = m1.lock();
    let _g2 = m2.lock();
    /* ... */
}

fn thread_b(m1: &Mutex<()>, m2: &Mutex<()>) {
    let _g1 = m2.lock();  // OPPOSITE ORDER
    let _g2 = m1.lock();
    /* ... */
}
```

If thread A holds `m1` and is waiting on `m2`, while thread B holds
`m2` and is waiting on `m1`, both threads block forever. This is the
canonical "lock ordering inversion" deadlock. The Rust compiler does
not detect it; the borrow checker only sees that each thread's borrows
are scoped correctly.

The "lock acquisition order discipline" is mandatory: every code path
that acquires multiple mutexes must acquire them in a globally-
consistent order. This is an *operational* discipline, not a *type-
system* one. Cross-link `race_conditions_concurrency_expertise.md` for
the cross-language lock-ordering discipline.

### 8.2 `std::sync::Mutex` poisoning on panic

A thread that panics while holding `std::sync::Mutex` *poisons* it.
Subsequent `lock()` returns `Err(PoisonError)`. The lock is still
acquirable via `PoisonError::into_inner()`, but the API forces the
caller to acknowledge possible state inconsistency.

Patterns:

- **`lock().unwrap()`** — panics on poison, compounding the original.
- **`lock().unwrap_or_else(|e| e.into_inner())`** — ignores poison;
  acceptable if state is robust to partial mutation.
- **`tokio::sync::Mutex`** — does *not* poison (cancellation is more
  common than panics in async).

Audit: every `Mutex::lock()` should handle `PoisonError` explicitly.
Neither default is universally correct — the choice is security-
relevant (does the panic indicate state corruption or not?).

### 8.3 `Arc<RwLock<T>>` writer starvation

`std::sync::RwLock`'s priority policy depends on the OS and is not
guaranteed, so steady reader streams may starve waiting writers. `parking_lot::RwLock` is
writer-preferring and faster but not in `std`.

Security relevance: token cache (readers) + key rotation (writer) with
reader-preferring locks can delay rotation arbitrarily. The window
between intended and actual rotation is unbounded.

### 8.4 `AtomicUsize::load` / `Ordering`

Rust atomics take `Ordering`:

- **`Relaxed`** — atomicity only; use for independent counters /
  advisory generation numbers.
- **`Acquire` / `Release`** — pairwise happens-before synchronization.
- **`AcqRel`** — RMW operations needing both.
- **`SeqCst`** — single global order across all threads. Conservative.

Footgun: `Relaxed` where `Acquire`/`Release` is needed. Works on x86
(strong ordering by default); fails on ARM (Apple Silicon, Graviton,
mobile). Audit rule: when in doubt, `SeqCst`. Justify `Acquire`/
`Release` via explicit publish/observe pairing; `Relaxed` only for
purely advisory state. Random `Relaxed` "because it's faster" is a
portability bug. Cross-link `race_conditions_concurrency_expertise.md`
§ memory-model discipline.

---

## 9. Panics + `unwrap` discipline

### 9.1 `unwrap()` and `expect()` — the panic primitives

`Option::unwrap` panics on `None`; `Result::unwrap` panics on `Err`.
`expect("msg")` is `unwrap` with a message.

In application code at the point of use, `unwrap` is often
appropriate: a panic-on-bug assertion. In *library* code it's almost
always wrong — libraries should propagate errors via `Result`. Library
`unwrap` on user input is a DoS surface.

`expect` messages should describe *the invariant violated*, not what
was expected. Bad: `value.expect("value should be Some")`. Better:
`value.expect("invariant: parser guarantees Some after successful
tokenization")`. Messages end up in production logs.

### 9.2 `panic!()` semantics — unwind vs abort

`panic` strategy from `Cargo.toml`:

- **`panic = "unwind"`** (default) — walks the stack, running `Drop`,
  until the thread terminates or `catch_unwind` catches.
- **`panic = "abort"`** — terminate immediately; smaller binaries,
  no cleanup.

Security implications: `unwind` runs `Drop` (closes FDs, releases
mutexes, flushes buffers) but a `Drop` panic during unwinding aborts
the process. `abort` is fail-fast but loses cleanup opportunities.

### 9.3 `catch_unwind` — works only on `panic = "unwind"`

`catch_unwind(closure)` returns `Ok(result)` or `Err(payload)`. Under
`panic = "abort"`, the process terminates before catching.

Common uses: FFI entry points (must not let panics cross C boundaries,
cross-link § 11); test harnesses; plugin systems.

Footgun: assuming `catch_unwind` always catches. Audit: pair with
explicit `Cargo.toml` `panic = "unwind"` for the relevant profile, or
document the conditional behavior.

### 9.4 Panic during `Drop` — process abort

`Drop` panic during normal scope exit propagates normally. `Drop`
panic during unwinding from a previous panic **aborts the process**
(double-panic is treated as unrecoverable corruption).

Audit: `Drop` impls should not panic. If they must (logging
assertions), use `if std::thread::panicking() { return; }`.

### 9.5 `unwrap` in production library code — anti-pattern

Most common Rust audit finding:

- `serde_json::from_str(&body).unwrap()` — DoS via malformed JSON.
- `users.iter().find(|u| u.id == id).unwrap()` — DoS via unknown ID.
- `s.parse::<u16>().unwrap()` — DoS via non-numeric input.

Fixes: `?` to propagate, `match` to handle, `unwrap_or(...)` for
defaults. Clippy `clippy::unwrap_used` flags all (off by default; on
in `restriction` group).

---

## 10. Integer overflow + arithmetic

### 10.1 Debug builds panic, release builds wrap

Rust integer arithmetic (`+`, `-`, `*`, `/`, etc.) behavior differs by
build profile:

- **Debug builds** (`cargo build`) — overflow panics with
  "attempt to add with overflow." This catches bugs during development.
- **Release builds** (`cargo build --release`) — overflow wraps as
  two's complement. No panic, no warning, just silently incorrect
  results.

This is the most common Rust "works in dev, breaks in production" bug
class. A subtle arithmetic bug that triggers overflow in production:

```rust
fn compute_offset(base: usize, length: usize) -> usize {
    base + length  // overflows silently in release if base + length > usize::MAX
}
```

If `compute_offset` is used as an index into a buffer, the wrapped
value is a small number that points into the *beginning* of the
buffer — not where the caller intended. Subsequent reads see
attacker-controlled data; subsequent writes corrupt the data at
`buf[wrapped_offset]`.

### 10.2 Explicit overflow methods

Identical behavior in debug and release:

- **`checked_add(o) -> Option<Self>`** — `None` on overflow.
- **`overflowing_add(o) -> (Self, bool)`** — wrapped result + flag.
- **`saturating_add(o) -> Self`** — caps at `T::MAX` / `T::MIN`.
- **`wrapping_add(o) -> Self`** — explicit, documented wrap.

Audit rule: arithmetic on external-input values (network, file, DB,
env) should use the explicit family. Default `+` only when range is
verified by other means.

### 10.3 `as` casts truncate silently

```rust
let big: u64 = 1_000_000_000_000;
let small: u32 = big as u32;  // silently 3567587328
```

Defined behavior (low-order bits) but silent. Clippy
`clippy::cast_possible_truncation` flags. Safer: `u32::try_from(big)`
returns `Result`; `u32::from(u16)` is infallible (only implemented for
non-truncating conversions).

### 10.4 `usize`-to-`isize` cast pitfalls

`usize::MAX` doesn't fit in `isize`; `large_usize as isize` produces a
negative number. Bites pointer-arithmetic where length × signed offset
yields UB. Fix: `try_into::<isize>()` or `i64`/`u64` intermediate
with bounds verification.

### 10.5 CVE patterns

- **Length-computation overflow** — `vec![0u8; user_count *
  sizeof_each]` wraps small; subsequent indexed writes. Safe `Vec`
  bounds-checks (panic-DoS); `unsafe` (`set_len`, `copy_nonoverlapping`)
  becomes a buffer overflow.
- **Price/quota overflow** — `total_cost` wraps small; user's balance
  debited by wrapped value. Cross-link
  `anti_fraud_abuse_engineering_expertise.md`.
- **Duration overflow** — next-fire-time earlier than now; scheduling
  loops CPU-spin.

### 10.6 Floating-point

- **`NaN != NaN`** — use `f64::is_nan()`.
- **`f64` is `PartialOrd`, not `Ord`** — can't use as `HashMap` /
  `BTreeMap` key directly. Use `OrderedFloat` or `f64::total_cmp`
  (1.62+).
- **`sin`/`cos`/`exp`/`log` non-determinism** — varies across
  libm/SVML/Intel libm. Consensus-critical code (blockchain) needs
  the `libm` crate for portable libm.

---

## 11. FFI boundaries

### 11.1 `#[no_mangle] pub extern "C" fn`

```rust
#[unsafe(no_mangle)]
pub extern "C" fn rust_compute(x: c_int) -> c_int { /* ... */ }
```

`#[no_mangle]` (now `unsafe(no_mangle)` in Rust 2024) disables name
mangling. `extern "C"` specifies the C ABI.

Audit hazards: calling-convention mismatch (`extern "system"` /
`"stdcall"` for Windows); type mismatch (use `c_int`/`c_char`); lifetime forging (returning
`&'static T` from a locally-constructed `T` is UB).

### 11.2 `*const c_char` vs `&str`

Rust strings are UTF-8 validated, not nul-terminated. C strings are
nul-terminated, no encoding guarantee.

- **C→Rust**: `let cstr = unsafe { CStr::from_ptr(c_ptr) };
  let s = cstr.to_str()?;` (fails on invalid UTF-8).
- **Rust→C**: `let cstring = CString::new(s)?; let ptr =
  cstring.as_ptr();` — fails on interior NUL.

`CString::as_ptr()` is valid only while the `CString` is alive. Common
UAF: `let ptr = CString::new(s).unwrap().as_ptr();` — `CString` is
dropped at the semicolon; `ptr` dangles. Fix: bind `CString` to a
local that outlives use.

### 11.3 Panics across FFI — UB

A Rust panic escaping a plain `extern "C"` fn aborts the process
(Rust 1.81+; previously UB).
Stabilized `extern "C-unwind"` (RFC 2945) allows it explicitly.

Audit pattern: every `#[unsafe(no_mangle)] pub extern "C" fn` should
wrap its body in `catch_unwind` and translate `Err` to an error code.
Without it, a panic aborts the process (Rust 1.81+).

### 11.4 `bindgen` — "trust your headers"

`bindgen` generates Rust FFI bindings from C headers. If the actual C
library differs from the header (reordered fields, added enum variants,
swapped arguments), the bindings are silently wrong → runtime memory
corruption with no compile-time signal.

Audit: verify header version pinned in `build.rs` matches the linked
library version.

### 11.5 `safer_ffi` and `cxx`

- **`safer_ffi`** — Rust bindings that prevent FFI panics, handle
  `CString` lifetimes, emit C headers from Rust signatures.
- **`cxx`** — Rust-C++ interop with bidirectional type-safe bindings
  via a shared schema; bridge handles destructor coordination.

Recommended for new Rust-FFI projects; hand-rolled `extern "C"` +
`bindgen` is the legacy default.

---

## 12. `serde` and deserialization

### 12.1 `#[derive(Deserialize)]` — convenient, not safe by default

Footguns in derived deserialization:

- **Unknown fields** are *ignored* by default. Attacker supplies
  `{"username": "x", "is_admin": true}` to an endpoint expecting
  `{"username"}` — `is_admin` is silently dropped unless the type uses
  `#[serde(deny_unknown_fields)]` (opt-in).
- **`#[serde(default)]`** lets attackers omit fields; they get the
  type's `Default`. Without it, missing fields fail deserialization.
- **Untagged enums** match the first variant that successfully
  deserializes — ambiguity resolves by source order.

Cross-link `deserialization_expertise.md`.

### 12.2 `serde_json::from_str(&data)`

Type-driven; rejects inputs that don't match `T`. Generally safe (no
code execution, contrast Python `pickle.loads`), but:

- **Numeric overflow** rejected (`u32` from `4294967296` → `Err`).
- **String allocation** unbounded by default — 10MB-string-from-1-line
  attack works. Pair with framework body-size limit
  (`RequestBodyLimitLayer`).
- **Recursive type stack-overflow** — `serde_json` has
  `RECURSION_LIMIT` (default 128).

Audit: every `from_str` call needs documented size + recursion limits.

### 12.3 Untagged enums + ambiguous input

```rust
#[derive(Deserialize)]
#[serde(untagged)]
enum Identity {
    User { username: String },
    Service { service_name: String, api_key: String },
}
```

Input `{"username": "alice", "service_name": "bob", "api_key": "k"}`
parses as `Identity::User`. If the application authz check trusts the
variant, the attacker has asserted user-level access while supplying
service-level fields. Fix: tagged enums (`#[serde(tag = "type")]`).
Cross-link `code_review_expertise.md` § auth-homogeneity.

### 12.4 `serde_yaml` archived; replacements

`serde_yaml` was archived by its maintainer in 2024. Replacements:
`serde_yaml_ng` or `serde_norway` (maintained forks); `yaml-rust2` (YAML 1.2).
`serde_yml` is not a replacement: RUSTSEC-2025-0068 (unsound, unmaintained).
Archival was maintenance burden, not security — both forks inherit
YAML's billion-laughs (anchor expansion) and YAML-1.1-implicit-type
(Norway-problem `"no"` → `false`) footguns.

Audit: codebases pinned to archived `serde_yaml` should migrate; no
upstream patches for future CVEs.

### 12.5 Bincode + format-version compatibility

`bincode` is non-self-describing. Bytes carry no type info; the
deserializer must know the schema.

Hazards: schema evolution has no built-in versioning (new field →
breaks old bytes); untagged enums unsupported
(`DeserializeAnyNotSupported`).

Cross-link `deserialization_expertise.md` § binary-versioning.

### 12.6 Self-describing binary alternatives

- **RON** — human-readable; preserves Rust type info.
- **MessagePack** (`rmp-serde`) — compact; cross-language.
- **CBOR** (`ciborium`) — RFC 8949.

All handle untagged enums + schema evolution better than `bincode`.

---

## 13. `Cargo.toml` and supply chain

### 13.1 `cargo install --git URL` — bypass crates.io

`cargo install --git https://example.com/repo` pulls source directly
from an arbitrary remote and compiles + installs it (running
`build.rs` and procedural macros) with the user's privileges. Audit:
git URLs in onboarding docs, Dockerfiles, or CI should pin to a
commit SHA, not a branch. Cross-link `cicd_supply_chain_expertise.md`
§ pin-to-SHA.

### 13.2 `build.rs` — arbitrary code at compile time

Every Rust crate may include `build.rs`, executed before the crate
compiles. It runs with the user's privileges and can read arbitrary
files, make network requests, spawn subprocesses, write filesystem
locations, modify `PATH`.

**`cargo build` on any Rust crate can lead to arbitrary code
execution** — equivalent to `npm install`'s `preinstall` scripts.

Audit: every direct dependency's `build.rs` should be reviewed. Crates
without `build.rs` are lower-risk. Crates whose `build.rs` performs
network I/O, file modification outside the build directory, or
environment-variable assignment are higher-risk. Tools:
`cargo-supply-chain`, `cargo-vet`.

### 13.3 `[patch.crates-io]` — silent dependency override

```toml
[patch.crates-io]
serde = { git = "https://github.com/my-fork/serde", branch = "patched" }
```

Cargo applies the patch silently — no downstream warning. Audit
hazard: a `[patch.crates-io]` is a place where a "trusted" dependency
is being replaced with a fork.

### 13.4 "Yanked" — not security

Yanked crate versions are excluded from new dependency resolution, but
existing `Cargo.lock` files still work; yanked source is still
downloadable; yanking is for compatibility, not vulnerabilities. Known-
insecure crates appear in the RustSec database with `RUSTSEC-YYYY-NNNN`
IDs.

### 13.5 crates.io — single-registry default

Unlike npm or PyPI, Rust defaults strongly to crates.io. Implications:
single point of failure/compromise; flat namespace → typosquatting
surface (enforcement reactive); abandoned crate names can't be
re-registered. Cross-link `cicd_supply_chain_expertise.md` § registry
security.

### 13.6 `cargo-audit` and the RustSec database

`cargo-audit` walks `Cargo.lock` and checks against RustSec
(`rustsec/advisory-db`). Each advisory has a `RUSTSEC-YYYY-NNNN` ID
mapping to CVEs where applicable.

`cargo audit` in CI on every PR + a scheduled daily job (catches
advisories landing after PR merge). 0.17.3+ supports `cargo audit bin` —
audits shipped binaries via `cargo auditable` embedded SBOM metadata.

### 13.7 Procedural macros — compile-time code execution

`#[derive(...)]` and attribute macros invoke proc-macros that run
during compilation. Same threat model as `build.rs`, plus the
proc-macro can inject backdoors that look like ordinary code into
the token stream.

Audit proc-macro dependencies as carefully as `build.rs`. `cargo
expand` shows expanded output; `cargo-vet` records audited crates.

---

## 14. `tokio` / async ecosystem footguns

### 14.1 `tokio::spawn` task disappearance

Dropped `JoinHandle` detaches the task; it keeps running with
unobservable result. Runtime shutdown drops detached tasks at next
await. "Fire-and-forget audit logging" can lose entries if the program
exits between spawn and flush. Audit: every `tokio::spawn` needs an
explicit handle lifecycle.

### 14.2 Mutex guard across `.await`

```rust
let mut guard = state.lock().await;
tokio::time::sleep(...).await;  // BAD
guard.modify();
```

Holds the mutex across suspension; other tasks block. With
`std::sync::Mutex` the guard is typically not `Send`, breaking
`tokio::spawn` compilation. Fix: drop the guard before `.await` or
use `tokio::sync::Mutex`. Clippy: `clippy::await_holding_lock`.

### 14.3 Blocking sync in async context

`std::fs::read`, `std::thread::sleep`, blocking-IO `from_reader`, and
CPU-bound work block the entire runtime worker. Fix: wrap in
`tokio::task::spawn_blocking` (dedicated thread pool).

Audit: grep `std::fs::`, `std::net::`, `std::thread::sleep` in async
contexts.

### 14.4 `block_on` inside async — runtime panic

`Runtime::block_on` from within an async fn panics: "Cannot start a
runtime from within a runtime." Common in tests sharing helpers.

### 14.5 Framework specifics

- **`hyper`** — request body is a stream of `Result<Bytes,
  hyper::Error>`; error-path mishandling is common.
- **`axum`** — extractor ordering rules (§ 15.1).
- **`actix-web`** — `web::Json<T>` has per-route size limits;
  defaults conservative but overridable.
- **`rocket`** — request-guard ordering rules.

Every framework has body-size limits with overridable defaults. Verify
configured limit matches the threat model; check for
"unlimited"-equivalent overrides.

---

## 15. Web framework specifics

### 15.1 Axum extractor ordering

Extractors fall in two categories:

- **`FromRequestParts`** — headers, URI, extensions; any order;
  composable.
- **`FromRequest`** — consumes body; **must be last**; one per handler.

`Json<T>` (body extractor) before a parts extractor is a compile
error — axum requires the body extractor to be the last argument.

### 15.2 Rocket request guards

Similar ordering rules: data guards (body-consumers) come after all
other guards.

### 15.3 `actix-web` `web::Json<T>` size limits

Default 2MB; per-route via `JsonConfig::limit(N)`. Audit: every
body-accepting route should set the limit explicitly even when it
matches the default — implicit defaults can change between versions.

### 15.4 `tower` middleware composition

`tower::Service` is the middleware abstraction. Common layers:
`TraceLayer`, `RequestBodyLimitLayer`, `CompressionLayer`,
`CorsLayer`.

Audit: middleware ordering matters for security. CORS before auth =
preflight succeeds for auth-required routes; CORS after auth =
unauthenticated preflight fails. Correct ordering depends on the
application but must be deliberate.

---

## 16. Detection patterns (Semgrep + cargo-audit + Clippy + MIRI)

### 16.1 Semgrep rule targets

- **`unsafe { ... }` density** — alert on new blocks.
- **`mem::transmute`** — prefer `bytemuck` / `zerocopy`.
- **`mem::forget` / `Box::leak`** — require comment explaining `Drop`
  suppression.
- **`MaybeUninit::uninit().assume_init()`** — read-back-uninit pattern,
  almost always a bug.
- **`unwrap()` in lib code** — panic-DoS surface.
- **`std::sync::Mutex::lock().unwrap()`** — unhandled poison.
- **Hardcoded crypto keys** — literal byte arrays passed to
  `aes::Aes256::new(...)`.
- **`tokio::spawn` without handle storage** — return value dropped.
- **`#[derive(Deserialize)]` without `#[serde(deny_unknown_fields)]`**
  in HTTP-handler types.

Cross-link `semgrep_rule_authoring.md`.

### 16.2 `cargo-audit`

CI on every PR + scheduled daily. RustSec database lands ~weekly
advisories. Configure ignores via `.cargo/audit.toml` with expiration
dates.

### 16.3 `clippy::pedantic` + `restriction`

Clippy groups: `correctness`, `suspicious`, `style`, `complexity`,
`perf` (on by default); `pedantic`, `restriction`, `nursery` (off).

For security audits enable `pedantic` plus selected `restriction`
lints: `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`,
`clippy::indexing_slicing`, `clippy::arithmetic_side_effects` (crypto-
adjacent), `clippy::float_arithmetic` (consensus-adjacent).

### 16.4 MIRI — the UB detector

Interpreter for Rust MIR. Detects pointer-provenance violations, type-
validity failures, data races, weak-memory orderings, Stacked/Tree
Borrows violations. 10x-1000x slower than native; typical workflow:
gated CI job on `unsafe`-heavy modules, possibly nightly.

POPL 2026 paper "Miri: Practical Undefined Behavior Detection for
Rust" documents design + production-impact studies.

### 16.5 `cargo-fuzz` and `afl.rs`

`cargo-fuzz` + libfuzzer; `afl.rs` + AFL. Use for parser-heavy code,
FFI boundaries, input-driven `unsafe`. Cross-link
`fuzzing_discipline_expertise.md`.

### 16.6 `cargo-geiger` and `dylint`

`cargo geiger` reports per-crate `unsafe` density in the dependency
tree. `dylint` distributes custom Clippy-style lints without forking
Clippy (Trail of Bits maintains a corpus). For organization-internal
audit discipline, `dylint` is the Rust-native pattern; Semgrep covers
cross-language rules.

---

## 17. Defensive checklist + variant analysis

### 17.1 Twelve-item Rust audit checklist

For every Rust codebase under review:

1. **Inventory `unsafe` blocks**. Run `rg '\bunsafe\b' --type rust`.
   Every block requires a documented safety contract and reviewer
   approval.
2. **Run `cargo-audit`**. Verify no known-CVE advisories on direct or
   transitive dependencies. Pin the audit to a CI job.
3. **Run `cargo-geiger`**. Compare `unsafe` density against the
   crate's purpose. Investigate outliers.
4. **Review `build.rs`** in every direct dependency. Note any
   network access, subprocess spawning, or `PATH` manipulation.
5. **Review `Cargo.toml` `[patch.crates-io]` and `git` dependencies**.
   Every override is a place where a trusted crate is being replaced;
   verify the replacement source is authorized.
6. **Verify `panic` profile**. `panic = "unwind"` for development,
   `panic = "abort"` for production-binary smaller-size, or vice
   versa depending on threat model. Verify `catch_unwind` is paired
   with `panic = "unwind"`.
7. **Enable Clippy at `pedantic` level** at minimum; select
   `restriction` lints (`unwrap_used`, `expect_used`, `panic`,
   `indexing_slicing`).
8. **Run MIRI on `unsafe`-heavy modules' tests** as a CI gated job.
   Every `unsafe` block should have at least one MIRI-validated test.
9. **Verify FFI boundaries**. Every `#[unsafe(no_mangle)] pub extern
   "C" fn` should wrap its body in `catch_unwind`. Every `CString` /
   `CStr` should have a documented lifetime story.
10. **Audit async cancellation**. Every `tokio::select!` arm should be
    cancellation-safe in its context. Every `tokio::spawn` should
    have an explicit `JoinHandle` lifecycle.
11. **Audit `serde` deserialization**. Every public-API
    `#[derive(Deserialize)]` should use `#[serde(deny_unknown_fields)]`
    unless the type is explicitly forwards-compatible.
12. **Audit lock discipline**. Every `Mutex::lock().unwrap()`
    handles poison explicitly. Every multi-mutex code path acquires
    in a globally-consistent order.

### 17.2 Variant analysis

When a Rust bug is found, search the codebase + dependencies for:

- **`assume_init` after partial fill** — verify initialization is total.
- **`transmute` between non-`#[repr(C)]` structs** — verify layout pinning.
- **`MutexGuard` across `.await`** — Clippy `await_holding_lock` catches most.
- **`unwrap` after attacker-influenced parse** — every `unwrap`/`expect`
  adjacent to network/file/DB reads.
- **Cross-FFI panics** — every `extern "C"` fn needs `catch_unwind`.

### 17.3 Edition-2024 + native async traits migration

- **Edition 2024** — `static_mut_refs` deny-by-default, `unsafe(attr)` for
  sound-critical attributes, tightened `if let` temporary lifetimes.
  Re-audit `static mut` and macro-generated code on migration.
- **Native async traits** (Rust 1.75+) — codebases mixing native and
  `async-trait` futures have subtle `Send`/`Sync` interactions.

### 17.4 Const generics

`fn foo<const N: usize>(x: [u8; N])` is stable (Rust 1.51).
`const fn` panics become compile errors — useful for invariant
enforcement. `generic_const_exprs` is nightly-only with edge-case
soundness work in progress; stick to stable.

### 17.5 Cross-link discipline

Read `code_review_expertise.md` (click-count severity);
`race_conditions_concurrency_expertise.md` (TOCTOU, lock ordering,
memory model); `firmware_embedded_security.md` (`no_std` / embedded);
`deserialization_expertise.md` (cross-language `serde`).

---

## 18. References

### Rust language and runtime

- The Rust Programming Language (3rd edition): https://doc.rust-lang.org/book/
- The Rustonomicon (advanced unsafe Rust): https://doc.rust-lang.org/nomicon/
- Unsafe Rust chapter (Book Ch. 20): https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html
- Rust Reference — Panic chapter: https://doc.rust-lang.org/stable/reference/panic.html
- Rust Reference — Behavior considered undefined: https://doc.rust-lang.org/stable/reference/behavior-considered-undefined.html
- `std::mem::transmute`: https://doc.rust-lang.org/std/mem/fn.transmute.html
- `std::mem::MaybeUninit`: https://doc.rust-lang.org/std/mem/union.MaybeUninit.html
- `std::pin`: https://doc.rust-lang.org/std/pin/index.html
- `std::sync::Mutex`: https://doc.rust-lang.org/std/sync/struct.Mutex.html
- `std::panic::catch_unwind`: https://doc.rust-lang.org/std/panic/fn.catch_unwind.html
- `std::ffi::CString`: https://doc.rust-lang.org/std/ffi/struct.CString.html
- `mem::forget`: https://doc.rust-lang.org/std/mem/fn.forget.html
- Leaking (Rustonomicon): https://doc.rust-lang.org/nomicon/leaking.html
- FFI (Rustonomicon): https://doc.rust-lang.org/nomicon/ffi.html

### Academic and operational-semantics work

- Stacked Borrows: An Aliasing Model for Rust (POPL 2020): https://plv.mpi-sws.org/rustbelt/stacked-borrows/paper.pdf
- Tree Borrows (PLDI 2025): https://iris-project.org/pdfs/2025-pldi-treeborrows.pdf
- Ralf Jung — From Stacks to Trees: A new aliasing model for Rust: https://www.ralfj.de/blog/2023/06/02/tree-borrows.html
- Miri: Practical Undefined Behavior Detection for Rust (POPL 2026): https://research.ralfj.de/papers/2026-popl-miri.pdf
- Ralf Jung PhD thesis "Understanding and Evolving the Rust Programming Language": https://research.ralfj.de/phd/thesis-screen.pdf
- Ralf Jung's blog: https://www.ralfj.de/blog/

### RFCs and language design

- RFC 0560 (Integer overflow): https://rust-lang.github.io/rfcs/0560-integer-overflow.html
- RFC 2349 (Pin): https://rust-lang.github.io/rfcs/2349-pin.html
- RFC 2835 (Project Safe Transmute): https://rust-lang.github.io/rfcs/2835-project-safe-transmute.html
- RFC 2945 (C-unwind ABI): https://rust-lang.github.io/rfcs/2945-c-unwind-abi.html
- RFC 2965 (Project Error Handling): https://rust-lang.github.io/rfcs/2965-project-error-handling.html
- RFC 3254 (Types Team): https://rust-lang.github.io/rfcs/3254-types-team.html

### Security advisory and tooling

- RustSec advisory database: https://rustsec.org/
- RustSec advisory-db repository: https://github.com/rustsec/advisory-db
- `cargo-audit` source: https://github.com/rustsec/rustsec/tree/main/cargo-audit
- `cargo-audit` blog (0.18 release): https://blog.rust-lang.org/inside-rust/2023/09/04/keeping-secure-with-cargo-audit-0.18/
- Cargo security advisory (CVE-2026-33056): https://blog.rust-lang.org/2026/03/21/cve-2026-33056/
- RUSTSEC-2018-0019 (actix-web): https://rustsec.org/advisories/RUSTSEC-2018-0019.html
- RUSTSEC-2019-0009 (smallvec double-free): https://rustsec.org/advisories/RUSTSEC-2019-0009.html
- RUSTSEC-2019-0012 (smallvec memory corruption): https://rustsec.org/advisories/RUSTSEC-2019-0012.html
- RUSTSEC-2020-0038 (ordnung): https://rustsec.org/advisories/RUSTSEC-2020-0038.html

### Static analysis and detection

- Rust Clippy lints index: https://rust-lang.github.io/rust-clippy/master/index.html
- Clippy source: https://github.com/rust-lang/rust-clippy
- Awesome Rust Checker list: https://github.com/BurtonQin/Awesome-Rust-Checker
- Rudra (SOSP 2021): https://dl.acm.org/doi/10.1145/3477132.3483570
- Rudra source: https://github.com/sslab-gatech/Rudra
- Static Analyzer Rudra coverage (InfoQ): https://www.infoq.com/news/2021/11/rudra-rust-safety/
- Trail of Bits Rust GitHub presence: https://github.com/trailofbits?language=rust
- Trail of Bits static-analysis blog: https://blog.trailofbits.com/categories/static-analysis/

### Async and tokio

- Tokio `select!` macro: https://docs.rs/tokio/latest/tokio/macro.select.html
- Tokio `Mutex`: https://docs.rs/tokio/latest/tokio/sync/struct.Mutex.html
- `CancellationToken`: https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html
- Oxide RFD 400 (Dealing with cancel safety in async Rust): https://rfd.shared.oxide.computer/rfd/0400
- Sunshowers — Cancelling async Rust: https://sunshowers.io/posts/cancelling-async-rust/
- Cybernetist — Rust tokio task cancellation patterns: https://cybernetist.com/2024/04/19/rust-tokio-task-cancellation-patterns/
- Tokio cancellation discussion (Comprehensive Rust): https://google.github.io/comprehensive-rust/concurrency/async-pitfalls/cancellation.html

### Pin and self-referential structs

- Cloudflare — Pin, Unpin, and why Rust needs them: https://blog.cloudflare.com/pin-and-unpin-in-rust/
- without.boats — Pin: https://without.boats/blog/pin/
- `pin-project` documentation: https://docs.rs/pin-project/latest/pin_project/attr.pin_project.html
- Yoshua Wuyts — Safe Pin Projections Through View Types: https://blog.yoshuawuyts.com/safe-pin-projections-through-view-types
- Pinning and Self-Referential Structs in Rust (Sling Academy): https://www.slingacademy.com/article/pinning-and-self-referential-structs-in-rust-avoiding-move-pitfalls/

### FFI and unsafe-Rust discipline

- Effective Rust — Control what crosses FFI boundaries: https://www.effective-rust.com/ffi.html
- Apriorit — Maintain Safety with Unsafe and C-interoperable Rust: https://www.apriorit.com/dev-blog/interoperability-unsafe-rust
- LogRocket — Unsafe Rust: How and when (not) to use it: https://blog.logrocket.com/unsafe-rust-how-and-when-not-to-use-it/

### Safe transmutation

- `zerocopy` docs: https://docs.rs/zerocopy/latest/zerocopy/
- LWN — Toward safe transmutation in Rust: https://lwn.net/Articles/994334/
- Project Safe Transmute RFC draft: https://github.com/rust-lang/project-safe-transmute/blob/master/rfcs/0000-safe-transmute.md
- Jack Wrenn — Safety Goggles for Alchemists: https://jack.wrenn.fyi/blog/safety-goggles-for-alchemists/

### Researcher corpora

- Aria Beingessner / Gankra writings (Faultlore): https://faultlore.com/blah/
- Gankra GitHub: https://github.com/Gankra
- Steve Klabnik website: https://steveklabnik.com/
- Manish Goregaokar writings: https://manishearth.github.io/
- Niko Matsakis (Rust Foundation): https://rustfoundation.org/media/introducing-the-rust-foundations-newest-project-directors-october-2025/
- Felix Klock II homepage: http://pnkfx.org/pnkfelix/
- Jane Lusby — Error Handling in Rust (Rustacean Station): https://rustacean-station.org/episode/047-jane-lusby/
- Jane Lusby — RustConf 2020 talk: https://www.youtube.com/watch?v=rAF8mLI0naQ
- Cargo security ramifications — Shnatsel: https://shnatsel.medium.com/do-not-run-any-cargo-commands-on-untrusted-projects-4c31c89a78d6

### Web frameworks

- Axum extract module: https://docs.rs/axum/latest/axum/extract/index.html
- Tokio website (runtime documentation): https://tokio.rs/
- Hyper documentation: https://hyper.rs/

### Cargo and supply chain

- Cargo book — Build Scripts: https://doc.rust-lang.org/cargo/reference/build-scripts.html
- Cargo book — Configuration: https://doc.rust-lang.org/cargo/reference/config.html
- `cargo-vet`: https://mozilla.github.io/cargo-vet/
- `cargo-geiger`: https://github.com/geiger-rs/cargo-geiger
- `cargo auditable`: https://github.com/rust-secure-code/cargo-auditable

### Cross-language adjacencies

- python_footguns_expertise.md — companion Python doc
- javascript_node_footguns_expertise.md — companion JS doc
- csharp_dotnet_footguns_expertise.md — companion C# doc
- java_footguns_expertise.md — companion Java doc
- ruby_footguns_expertise.md — companion Ruby doc
- php_footguns_expertise.md — companion PHP doc
