# C and C++ Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from CERT / NCC Group standards authors, the John Regehr undefined-behavior canon, the C++ Core Guidelines editors, the TAOSSA candidate-point auditing tradition, and the institutional advisories that have catalogued C/C++ memory-safety failure modes for thirty years

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — companion docs cover C#/.NET,
> Java, Python, JavaScript/Node, PHP, and Ruby. C and C++ are placed last in the
> series intentionally: they have more behavioral surface than the higher-level
> languages combined, and the bulk of that surface is *load-bearing* (the
> language is used precisely because the default is "the compiler will not save
> you"). The 2024-2026 load-bearing updates are: signed-integer-overflow
> sanitizer adoption shifting from opt-in to default in major distros, the
> arrival of `-fbounds-safety` for C and the C++ Safety Profiles work,
> Microsoft's CHERIoT and Arm's Morello reaching production-adjacent maturity,
> Apple's Memory Integrity Enforcement (MIE) shipping on iPhone 17 Pro, and the
> CISA / NSA / ONCD push to label memory-unsafe languages as a *strategic*
> liability in critical infrastructure (rather than a per-bug problem).
>
> **Researchers:**
> - **Robert C. Seacord** — Technical Director, NCC Group (formerly CERT/SEI);
>   author of "Secure Coding in C and C++" (Addison-Wesley, 2nd ed. 2013) and
>   "The CERT C Coding Standard" (2nd ed., 2014, 98 rules); ISO/IEC JTC1/SC22/WG14
>   C-standards-committee participant; teaches secure-coding training at Black
>   Hat. The canonical institutional voice on memory-safety, integer-overflow,
>   and string-handling defects in C/C++
> - **John Regehr** — Professor, University of Utah; co-founder TrustInSoft;
>   author of the "A Guide to Undefined Behavior in C and C++" three-part blog
>   series (2010) that became the field-defining tutorial on UB; principal
>   investigator on the CSmith random C-program generator that found hundreds
>   of compiler bugs in GCC and Clang; "It's Time to Get Serious About
>   Exploiting Undefined Behavior" (2012)
> - **Pascal Cuoq** — Co-founder and Chief Scientist, TrustInSoft; principal
>   author of the TIS Interpreter and Frama-C plug-ins for sound static
>   analysis of C; co-authored the "Defining the Undefinedness of C" line of
>   work with Regehr; the canonical reference on formal C semantics applied
>   to real codebases
> - **Mark Dowd, Justin Schuh, John McDonald** — co-authors of *The Art of
>   Software Security Assessment* (Addison-Wesley, 2006), the canonical
>   manual on candidate-point auditing of C/C++ codebases; chapters 6-8
>   (memory corruption), 9 (UNIX I/O), 10 (Windows APIs), and 13 (synchronization)
>   remain the field reference on auditor-side reasoning about C/C++ defects.
>   Dowd is now founder of Aleph Research / former Azimuth Security; Schuh
>   led Chrome Security at Google; McDonald is at Hyatt Information Security
> - **Bjarne Stroustrup** — Designer of C++ and Managing Director, Technology
>   Division, Morgan Stanley; co-editor of the **C++ Core Guidelines** with
>   Herb Sutter, the canonical "use C++ well" document; author of "The Design
>   and Evolution of C++" (1994) which documents the rationale (and explicit
>   constraints) behind each design decision that produces a present-day
>   footgun
> - **Herb Sutter** — Chair, ISO C++ Standards Committee; co-editor of the
>   C++ Core Guidelines; author of "Exceptional C++" series (Addison-Wesley)
>   that codified the strong vs. basic vs. nothrow exception-safety taxonomy;
>   2023-onward author of the C++ Safety Profiles / "Carbon-adjacent" successor
>   proposals
> - **Chris Lattner** — Founder of LLVM, Clang, Swift, and Mojo; the canonical
>   "what does the optimizer assume about UB" voice; the 2011 LLVM blog series
>   "What Every C Programmer Should Know About Undefined Behavior" (3 parts) is
>   the single best source on how UB enables optimization and why "if you
>   invoke UB the compiler assumes you didn't" is not a bug but the design
>   contract
> - **James Forshaw, Mark Brand, Natalie Silvanovich, Ian Beer, Tavis Ormandy**
>   (Google Project Zero) — long-running exploit-research corpus on C/C++
>   parsers, kernel surfaces, browser engines, and OS subsystems; the Project
>   Zero blog is the canonical empirical record of which C/C++ footguns
>   matter in practice and which are mostly theoretical
> - **Trail of Bits** (Dan Guido, Stefan Edwards, Peter Goodman, Artem Dinaburg)
>   — practitioners who maintain the empirical-grade C/C++ audit corpus
>   underlying many of the toolchain pieces (manticore, cb-multios, the McSema
>   binary lifter); Goodman's work on Souffle-based program analysis is the
>   academic-to-industrial bridge for many of the static-analysis primitives
>   discussed in §15
> - **Saar Amar, Tony Chen, Robert Watson** (Microsoft Azure Silicon / Cambridge)
>   — CHERIoT and Morello industrial-grade CHERI implementations; the
>   load-bearing institutional voices on "what would memory-safe C/C++
>   actually look like in deployed silicon"
> - **Damien Miller, Todd C. Miller** — OpenBSD project; original `strlcpy` /
>   `strlcat` authors (1998 USENIX paper); the canonical "what the standard
>   C library should have looked like but didn't" reference
> - **Konstantin Serebryany, Kostya Yashinsky, Alexander Potapenko** (Google) —
>   AddressSanitizer, ThreadSanitizer, MemorySanitizer, LeakSanitizer, and
>   UndefinedBehaviorSanitizer authors; the institutional voices on what
>   *can* be caught dynamically and at what overhead cost
>
> **Institutional contributors:** MITRE CWE (the entire CWE Top 25 is C/C++-
> dominant: CWE-787 OOB Write, CWE-79 XSS, CWE-89 SQLi, CWE-416 UAF, CWE-78
> OS Cmd Inj, CWE-20 Improper Input, CWE-125 OOB Read, CWE-22 Path Traversal,
> CWE-352 CSRF, CWE-434 Unrestricted Upload — at least five of those have C/C++
> as their dominant ecosystem); CERT C and C++ Secure Coding Standards (SEI/CMU);
> the **C++ Core Guidelines** (Stroustrup + Sutter, isocpp.github.io); the **C
> Memory-Safe Roadmap** / **C++ Safety Profiles** (P3081 et al.); Microsoft
> Security Response Center retrospectives (the canonical "~70% of MSRC-tracked
> CVEs are memory-safety defects in C/C++" figure); Google Chrome / Android
> security retrospectives (parallel figure); NSA "Software Memory Safety"
> cybersecurity advisory (2022); CISA "Product Security Bad Practices" 2024
> guidance flagging "use of memory-unsafe languages" as a Bad Practice for
> critical-infrastructure software.
>
> **What this doc is NOT:** not a C or C++ language tutorial; not a memory-
> corruption exploitation manual (see `linux_kernel_exploitation_expertise.md`
> and `macos_memory_corruption_investigation.md` for the offensive side); not
> a fuzzing manual (see `fuzzing_discipline_expertise.md`); not a substitute
> for sanitizers or static analyzers (it complements them). It is the
> language-specific layer beneath cross-language audit heuristics: what
> primitives are *unsafe by default*, what the auditor should treat as a
> candidate point, and what the developer should treat as an alarm bell.

Cross-links: see `code_review_expertise.md` for the click-count severity
heuristic and the Mark Dowd candidate-point auditing pattern (this doc is
the C/C++-specific elaboration of §2 there); `race_conditions_concurrency_expertise.md`
for the cross-language treatment of data races and synchronization
primitives; `fuzzing_discipline_expertise.md` for the sanitizer + fuzzer
combination that catches the bulk of these footguns dynamically;
`hardware_side_channels_expertise.md` for PAC, MTE, CET, and the
hardware-mitigation context; `firmware_embedded_security.md` for the
embedded-C subset where many of these footguns persist longest;
`linux_kernel_exploitation_expertise.md` for the kernel-side exploitation
implications; `macos_memory_corruption_investigation.md` for the heap-spray
and reproducer-workflow side; `semgrep_rule_authoring.md` for the
detection-rule-authoring guidance referenced from §15.

---

## 1. The behavioral-footgun framing

### 1.1 Why C and C++ deserve a denser doc

The other footgun docs in this series average ~63K and ~14-16 sections.
This one targets 55-70K because C and C++ have *more behavioral surface*
than any of the higher-level languages, and most of that surface is
load-bearing rather than incidental. The footgun count is not a quality
defect of C and C++ — it is the price the languages pay for the design
goals (no runtime overhead the programmer didn't ask for, full control
over memory and lifetime, "trust the programmer" as an explicit
principle). That tradeoff was a reasonable bet in 1972 and even in
1985, and the resulting codebases still run the bulk of the world's
critical infrastructure.

This doc is therefore *not* a polemic against C or C++. It is an
auditor's and developer's reference for which primitives are unsafe
by default in a security-relevant context, so the reader can recognize
candidate points (Dowd / Schuh / McDonald sense) on a code reading
pass and can make the fix or escalate appropriately.

### 1.2 The "permitted to do anything" axiom

The single most important fact about C and C++ behavioral footguns is
the **undefined-behavior contract**: when the program invokes UB, the
ISO C and ISO C++ standards impose *no* requirement on what the
implementation must do. The program is permitted to do anything,
including: produce the "obvious" result, produce a different result,
silently corrupt memory, crash, format the disk, or — most commonly —
have the optimizer assume the UB *cannot have occurred* and remove
nearby code accordingly. This last consequence is the one that
surprises developers most often, and the one Regehr's blog series
catalogued most thoroughly. See the [LLVM "What Every C Programmer
Should Know About Undefined Behavior" series][lattner-ub] and the
[Regehr "A Guide to Undefined Behavior in C and C++" series][regehr-ub-1].

[lattner-ub]: https://blog.llvm.org/2011/05/what-every-c-programmer-should-know.html
[regehr-ub-1]: https://blog.regehr.org/archives/213

This axiom propagates: every primitive whose default behavior
**permits** UB on some input is a footgun, because the auditor cannot
inspect the source of every input to every call site. The auditor
must instead treat the call site as a candidate point and prove
absence-of-UB locally, or replace the primitive with one whose default
behavior is total (i.e., defined on all inputs). The C++ Core
Guidelines and the CERT Secure Coding Standards are both organized
around "make the default behavior total, escape to UB only at narrow
documented boundaries."

### 1.3 The audit-cost asymmetry (carry-forward from the C# doc)

The developer writes `strcpy(dst, src)` once and "knows" `src` is
short enough. The auditor reads it many times and has to *prove* that
across every caller — including the future caller who hasn't been
written yet. The footgun is primarily a review and maintenance
problem, not a write problem. C/C++ amplifies this asymmetry compared
to the higher-level languages: there is no runtime check that will
turn the bug into a controlled exception, and the bug class
(OOB write, UAF, double-free, signed overflow, strict-aliasing
violation) does not localize the way a higher-level language's bug
class does — a single overflow can corrupt unrelated state arbitrarily
far away from the call site, and the symptom may surface in a
seemingly-unrelated component.

Cross-link to `code_review_expertise.md` §2 ("Mark Dowd candidate-point
auditing"): every primitive listed in this doc is a *candidate point*
in the Dowd sense — a single source-line whose correctness depends on
non-local properties of the surrounding code, and which therefore
needs to be enumerated explicitly during a review.

### 1.4 The detection-coverage gap

A useful framing for the doc: not every footgun is created equal in
how easily it can be caught. The footguns split roughly into:

- **Dynamic-detectable with sanitizers** (ASan, UBSan, MSan, TSan):
  OOB read/write, UAF, double-free, signed overflow with `-fsanitize=signed-integer-overflow`,
  uninitialized memory reads (MSan only), data races (TSan only),
  most UB enumerated in the standard. **Hit rate depends on test
  coverage** — sanitizers only catch what the test suite or fuzzer
  exercises.
- **Static-detectable with a sound analyzer** (Frama-C, TIS-Interpreter,
  Clang Static Analyzer, Coverity, CodeQL, PVS-Studio): a subset of
  the above, plus some lifetime / aliasing / null-deref defects.
  **Hit rate depends on annotation density and the analyzer's
  precision-recall tradeoff** — sound analyzers report on every
  possible path including infeasible ones; unsound ones miss real
  defects.
- **Static-detectable with a pattern matcher** (Semgrep, grep): the
  banned-primitive set (strcpy, gets, sprintf, format-string-from-user)
  and the named-API misuse set (`Path.Combine`-equivalent —
  `realpath`, `chroot`, `umask` ordering). **Hit rate is high on the
  banned-primitive set, low on the misuse set.**
- **Detectable only by code review or formal proof**: ownership
  defects, complex lifetime defects, ABI / ODR violations, race
  conditions on non-atomic shared state, design defects (using a
  non-thread-safe API across threads, using a non-reentrant API in a
  signal handler).

§15 walks the detection-coverage table per footgun-class.

### 1.5 The 70% statistic

Microsoft Security Response Center (MSRC) retrospectives have
consistently reported that ~70% of MSRC-tracked CVEs each year are
memory-safety defects (BlueHat IL 2019, Trent Jaeger's BlueHat 2022
retrospective). Google's Chrome and Android teams report the same
~70% figure. The CHERI University-of-Cambridge "70% of security
vulnerabilities" figure (referenced in [the CHERI memory safety
paper][cheri-memory-safety]) is the canonical institutional summary.
This figure is the principal motivator for the NSA's 2022
"Software Memory Safety" cybersecurity advisory and CISA's 2024
"Product Security Bad Practices" guidance flagging memory-unsafe
languages as a Bad Practice for critical-infrastructure software.

[cheri-memory-safety]: https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/20240419-ieeesp-cheri-memory-safety.pdf

---

## 2. Undefined behavior — the master class

This is the single longest section in the document because UB is the
master class that the rest of the document specializes. A footgun is
nearly always "some user-reachable path causes UB, and the compiler
optimizes assuming you didn't, producing a security-relevant gap."

### 2.1 The contract

ISO C99 and later define UB as "behavior, upon use of a nonportable
or erroneous program construct or of erroneous data, for which this
International Standard imposes no requirements." Permissible
behaviors include: "ignoring the situation completely with
unpredictable results, behaving during translation or program
execution in a documented manner characteristic of the environment
(with or without the issuance of a diagnostic message), terminating a
translation or execution (with the issuance of a diagnostic
message)." ISO C++ uses the same form of words.

The auditor should read "imposes no requirements" literally: the
compiler may produce a binary that does whatever it likes on inputs
that trigger UB. The "common-sense" output (what the developer
*expected* the operation to do, e.g. `INT_MAX + 1 == INT_MIN`) is
*one* permissible output, but is not the only or even most likely
one. Modern optimizing compilers actively use the absence of UB as
an optimization premise.

### 2.2 The "you didn't invoke UB" optimization premise

The compiler's optimizer is permitted to assume the program does
*not* invoke UB. Therefore: any code that is reachable only on a
UB-invoking path can be proven dead, and removed. Any branch that
depends on a UB-sensitive expression can be folded to the
non-UB-invoking value.

The canonical example, from Regehr's series:

```c
int foo(int x) {
    if (x + 100 < x) return -1;  // overflow check
    return x + 100;
}
```

A modern optimizer with `-O2` will reason: "signed overflow is UB; if
`x + 100` overflows the program is in UB-land; therefore the
compiler may assume `x + 100` does not overflow; therefore
`x + 100 < x` is equivalent to `100 < 0`, i.e. false; therefore the
return-`-1` branch is dead." The check is silently elided, and a
caller relying on it to gate a downstream use of `x + 100` (e.g. as
a buffer length) gets the unprotected use.

This is not a compiler bug. It is the compiler doing exactly what
the standard permits. The defect is in the source code: the check is
in *post-overflow* form, and post-overflow checks are unreliable
because they are themselves UB on the overflowing input.

[Linux kernel CVE-2009-1897][linux-tun-bug] (the `tun` driver
null-pointer-deref) is the canonical institutional example of an
optimizer eliding a safety check on UB grounds. The kernel had
checked `tun->sk == NULL` *after* dereferencing `tun->sk->...`; the
optimizer reasoned that if `tun->sk` were null the deref would have
been UB, therefore `tun->sk` was non-null, therefore the subsequent
null check was dead, therefore the check was elided. An attacker
could trigger the null pointer and bypass the (now elided) check.

[linux-tun-bug]: https://lwn.net/Articles/342330/

### 2.3 The full UB catalog (selected)

The C standard lists ~200 specific behaviors as undefined. The
security-relevant subset is approximately the following list. Each
item is a category that the rest of this doc treats in more depth.

- Signed integer overflow (§3)
- Null pointer dereference
- Division by zero (and `INT_MIN / -1`, which overflows)
- Reading uninitialized automatic storage (§6)
- Out-of-bounds array access — read or write (§5)
- Pointer arithmetic past the one-past-the-end of an array (§5)
- Pointer comparison or subtraction across distinct objects (§5)
- Strict-aliasing violations (§4)
- Modifying a `const`-qualified object via a non-`const` access
- Modifying a string literal (§9)
- Use after free (§6)
- Double free (§6)
- Free of a pointer not returned by `malloc`/`calloc`/`realloc`
- Data race on a non-atomic shared object (§12)
- Calling a function via a pointer of incompatible type
- Returning from a non-`void` function without a `return` statement,
  when the caller uses the value
- Reaching the end of `main` in a non-`int` return form, or
  reaching the end of a non-`void` non-`main` function and using the
  result
- Stack overflow (the standard does not require diagnosis)
- Signed left shift overflow, or shift by a negative or
  greater-than-or-equal-to-width amount
- Modifying an object more than once without an intervening sequence
  point (C11+: "unsequenced side effects")

The C++ standard adds (selected):

- Recursion that exceeds the implementation's stack budget
- Throwing across an `extern "C"` boundary
- Throwing from a destructor during stack unwinding (§10)
- Calling a virtual function from a constructor or destructor of an
  abstract base class (UB), or expecting dynamic dispatch in such a
  call (well-defined, but does *not* dispatch to the derived class)
- Use of a moved-from object in a way that violates the type's
  documented post-move contract (well-defined for std types, UB or
  unspecified for user types depending on the type)
- Accessing a `std::variant` or `std::optional` via the wrong
  alternative (`std::variant::get<T>` throws `std::bad_variant_access`;
  `std::optional::value()` on empty throws `std::bad_optional_access`;
  `*opt` on empty `optional` is UB; `std::get_if` is the
  null-returning safe accessor)
- Dereferencing an end iterator
- Iterator invalidation after container mutation (§11)

### 2.4 The auditor's stance

For every primitive in the rest of this document, the auditor's
question is: "does this call site invoke UB on any input the
attacker can influence?" If yes, the call site is a candidate
point. The fix is either to make the input untainted (validate /
sanitize), to use a primitive whose default behavior is total
(`std::optional::value()` instead of `*opt`, `std::vector::at()`
instead of `operator[]`, `memcpy` instead of pointer-cast type
punning), or to add an explicit *pre-condition* check that runs
before the UB-prone operation.

The single biggest source of audit confusion in C/C++ is the
**post-condition check** anti-pattern: the developer writes the
operation and *then* tries to detect whether it overflowed,
underflowed, or aliased. Post-condition checks are unreliable in
the presence of UB because the optimizer is permitted to remove them.
**Pre-condition checks** — checked before the operation, expressed
in terms of the operands rather than the result — are the only
reliable form. CERT INT32-C documents this in detail.

Cross-link: this is the §2 "compiler-will-let-you axiom" of the C#
behavioral footguns doc, generalized. In C/C++ the axiom is
strictly stronger because the compiler is *permitted* to actively
exploit the absence of UB for optimization, not merely fail to
detect the bug.

---

## 3. Signed integer overflow

Signed integer overflow is the most-cited C/C++ footgun, both because
it is the simplest to demonstrate and because it is the canonical
example of the §2.2 optimization-premise consequence.

### 3.1 The rule

- Signed integer arithmetic that produces a value outside the
  representable range is **undefined behavior** in C and C++.
- Unsigned integer arithmetic that overflows is **defined**: it
  wraps modulo `2^N` where N is the width.

This asymmetry is a 1989-era ANSI/ISO C committee compromise: signed
representations were not yet standardized (the standard allowed
one's-complement, two's-complement, or sign-magnitude until C23 made
two's-complement mandatory), so the committee declared signed
overflow undefined to permit any of them. The optimization
consequences were not the original motivation but became the
load-bearing reason the rule was preserved.

### 3.2 The optimization trap

The §2.2 `x + 100 < x` example is the canonical case. Variants
include:

```c
// Compiler reasons: if i+1 overflows, UB; UB-free path: i+1 > i; therefore loop runs forever.
for (int i = 0; i + 1 > i; i++) { ... }

// Compiler reasons: a*4/4 == a iff a*4 doesn't overflow; UB-free path: result == a; folded.
int f(int a) { return a*4 / 4; }

// Compiler reasons: if 0 - i overflows (i.e. i == INT_MIN), UB; UB-free path: -i is well-defined; therefore abs returns a non-negative int.
int my_abs(int i) { return (i < 0) ? -i : i; }  // INT_MIN edge case
```

In every case, the developer's mental model ("the compiler will do
the obvious thing on overflow") is wrong, and the produced binary
silently violates that model.

### 3.3 The safe forms

**Pre-condition check:**

```c
// CERT INT32-C compliant: check operands, not result.
if (a > 0 && b > INT_MAX - a) { /* would overflow */ }
if (a < 0 && b < INT_MIN - a) { /* would underflow */ }
sum = a + b;
```

**Compiler intrinsics:**

```c
int sum;
if (__builtin_add_overflow(a, b, &sum)) { /* overflowed */ }
// MSVC: SafeInt class library or <intsafe.h>
// C23: ckd_add(), ckd_sub(), ckd_mul() in <stdckdint.h>
```

**Wider intermediate:**

```c
int64_t result = (int64_t)a + (int64_t)b;
if (result > INT_MAX || result < INT_MIN) { /* would overflow on narrow */ }
```

**Unsigned arithmetic** (if wrap-on-overflow is the desired
semantics): use `unsigned int` or `uint32_t`. Wrap is defined for
unsigned types.

### 3.4 Sanitizer coverage

`-fsanitize=signed-integer-overflow` (UBSan): traps at runtime on
overflow. Adoption is increasing — many distros now build with it
on for testing, and Apple's `-fbounds-safety` includes integer-
overflow trapping in the production-build subset.

### 3.5 The CVE corpus

CVE-2009-1897 (Linux `tun` driver) is the canonical optimization-
elided-check case. CVE-2017-15924 (Linux KEYS subsystem), CVE-2024-1086
(Linux nf_tables, a different bug-class but with an overflow component),
and a large slice of the Chrome / V8 / WebKit corpora include signed-
overflow primitives at the candidate-point level.

---

## 4. Strict aliasing and type punning

### 4.1 The rule

The C standard (§6.5/7) and the C++ standard (similar) specify
which **lvalue types** are permitted to access an object's stored
value. If you access an object through a pointer of an incompatible
type, the behavior is **undefined**. This is the **strict aliasing
rule**.

Permitted accesses (selected):
- The dynamic type of the object
- A `signed` or `unsigned` qualified version of the dynamic type
- A `const` or `volatile` qualified version of the dynamic type
- A character type (`char`, `signed char`, `unsigned char`,
  `std::byte` in C++17+) — character types may alias anything

Everything else is UB.

### 4.2 The classic violation

```c
float f = 3.14f;
int i = *(int*)&f;  // strict-aliasing violation: reading float-typed
                     // object through int-lvalue is UB
```

The "obvious" mental model — "read the bits as an int" — is exactly
what the developer wants, but the strict-aliasing rule forbids it.
On `-O2`, the compiler is permitted to assume `i` and `f` cannot
alias (they have incompatible types), and may reorder loads and
stores accordingly, producing surprising output.

The Regehr "Type Punning, Strict Aliasing, and Optimization"
blog post documents the optimization consequences. The compiler
may *appear* to do the right thing in a simple example and fail in
a complex one, which makes the bug particularly insidious.

### 4.3 The safe forms

**`memcpy`** (works in C and C++):

```c
float f = 3.14f;
int i;
memcpy(&i, &f, sizeof i);  // defined; compiler elides the memcpy on -O2
```

The compiler is permitted (and required, on essentially every
optimizer) to compile this to a single load — there is no runtime
cost. The `memcpy` is purely a *language-level* annotation that
says "I am intentionally reading the bytes of one type as another."

**`std::bit_cast`** (C++20):

```cpp
#include <bit>
float f = 3.14f;
int i = std::bit_cast<int>(f);  // defined; constexpr; checks size + triviality
```

Strictly preferred in modern C++ because it also enforces that the
two types have the same size and are trivially copyable.

**`union` type punning**:
- **In C**: allowed (since C99 TC3). Write to one member, read from
  another: defined.
- **In C++**: **undefined**. The standard says reading from a
  non-active member of a union is UB. (Compilers commonly *implement*
  it as the C semantics, but the standard does not require it.)

### 4.4 The `-fno-strict-aliasing` escape

GCC and Clang offer `-fno-strict-aliasing`, which disables the
compiler's strict-aliasing-based optimizations. The Linux kernel,
some BSDs, and large parts of the FFmpeg codebase build with this
flag. The tradeoff is a measurable (~5-15%) optimization loss on
some workloads.

For a new codebase, this is not the recommended path: use
`memcpy` / `std::bit_cast`. For an existing codebase that has
already been written assuming the un-strict rule, the flag is the
cheap fix.

### 4.5 Auditor's checklist

- Any `*(T*)&x` or `(T*)p` cast in a hot path is a candidate point.
- `union` punning in a C++ codebase is a candidate point.
- Network packet parsing that reads multi-byte fields by casting
  the buffer pointer to a struct pointer is a candidate point —
  use `memcpy` to a struct on the stack.
- Reading `float` bits as `int` (e.g. for fast inverse square root)
  is a candidate point unless `memcpy` or `bit_cast` is used.

---

## 5. Pointer arithmetic and array decay

### 5.1 Array-to-pointer decay

```c
void f(int arr[10]) { sizeof(arr); }  // sizeof(int*), NOT 10*sizeof(int)
```

The function parameter declaration `int arr[10]` is *exactly
equivalent* to `int *arr`. The `10` is documentation, ignored by
the compiler. Inside the function, `arr` is a pointer, not an
array, and `sizeof(arr)` is the size of a pointer.

The `sizeof(arr) / sizeof(arr[0])` idiom for "number of elements"
works only when `arr` is an *actual array* in the same scope, not
a pointer. Crossing a function boundary loses the array length,
which is the root cause of most "passed wrong length, overran the
buffer" defects in C.

C++17's `std::size(arr)` and `<iterator>` machinery use template
type deduction to refuse to compile if `arr` is not an actual
array — strictly preferred over the divide-by-sizeof idiom.

### 5.2 Pointer arithmetic across object boundaries

```c
int a, b;
intptr_t diff = (&a) - (&b);  // UB: subtraction across distinct objects
```

Pointer subtraction is defined only when both pointers point into
the same array (or one past the end). Subtracting two pointers from
distinct objects is UB. Comparison with `==` / `!=` is defined;
ordering (`<`, `>`, `<=`, `>=`) is unspecified or UB across distinct
objects.

This rule is what makes generic pointer-based data structures (e.g.
intrusive linked lists with arithmetic) inherently unsafe to write
in standards-compliant C/C++. The `container_of` macro used in the
Linux kernel is, strictly speaking, UB by the standard, and the
kernel relies on compiler-specific extensions to make it well-defined.

### 5.3 The one-past-the-end exception

A pointer to one element past the end of an array is **defined to
exist** (it can be computed, compared, and subtracted from
pointers into the array). **Dereferencing** that pointer is UB.

```c
int arr[10];
int *p = &arr[10];   // OK
int *q = arr + 10;   // OK
int v = *p;           // UB: dereferencing one-past-the-end
```

This is the idiom that makes C-style iteration (`for (p = arr; p != arr + 10; p++)`)
well-defined: the *comparison* with `arr + 10` is fine; the *dereference*
of `*p` inside the loop body only happens on `p < arr + 10`.

### 5.4 The `restrict` keyword

C99's `restrict` keyword (and the equivalent `__restrict__` extension
in C++) is the developer's promise to the compiler that two pointers
do not alias. Violating the promise is UB. `memcpy` is declared
with `restrict` parameters, which is why calling
`memcpy(dst, src, n)` where `dst` and `src` overlap is UB (use
`memmove` instead).

### 5.5 Auditor's checklist

- Any function parameter declared as an array `T param[N]` should
  be read as `T *param`; the length must be passed separately.
- Any `sizeof(arr) / sizeof(arr[0])` inside a function should be
  audited: is `arr` an array in the same scope, or a pointer
  parameter?
- Any pointer subtraction is a candidate point: are both pointers
  into the same object?
- `restrict` annotations are *promises*; violating them is UB and
  is often a silent bug.

---

## 6. Memory allocation lifecycle

### 6.1 The C side

- `malloc(n)`: returns pointer to `n` bytes of uninitialized
  memory, or `NULL` on failure.
- `calloc(n, sz)`: returns pointer to `n * sz` bytes of zeroed
  memory, or `NULL` on failure. `n * sz` may overflow, in which
  case `calloc` is required to return `NULL` (this is one of the
  few cases where the library has overflow checking).
- `realloc(p, n)`: requests resizing. On success, returns the
  (possibly different) pointer; the original is invalidated. On
  failure, returns `NULL` and **the original pointer remains valid**.
  The most common `realloc` bug is `p = realloc(p, n);` — if
  `realloc` returns `NULL`, `p` is overwritten with `NULL` and the
  original allocation is leaked. The safe form: `tmp = realloc(p, n); if (tmp) p = tmp;`.
- `free(p)`: deallocates. `free(NULL)` is well-defined and is a
  no-op.
- **Double free** of the same pointer is UB.
- **Use after free** (any access to the freed allocation) is UB.

### 6.2 The C++ side

- `new T`: allocates and constructs. Returns `T*`. Throws
  `std::bad_alloc` on allocation failure.
- `new T[N]`: allocates and constructs an array.
- `delete p`: destructs and deallocates the *single object* `p`.
  `delete nullptr` is well-defined and is a no-op.
- `delete[] p`: destructs and deallocates the *array* `p`.
- `delete` on a pointer obtained from `new[]` is UB.
- `delete[]` on a pointer obtained from `new` is UB.
- `free` on a pointer obtained from `new` is UB.
- `delete` on a pointer obtained from `malloc` is UB.

The C/C++ ABI boundary rule is: **whichever flavor allocated must
free.** A C library that returns a `malloc`-ed pointer must be
freed with `free`, not `delete`; a C++ library that returns a
`new`-ed pointer must be deleted with `delete`. Mixing across the
boundary is UB.

### 6.3 The polymorphic-deletion trap

```cpp
struct Base { /* no virtual destructor */ };
struct Derived : Base { /* has resources */ };

Base *p = new Derived();
delete p;  // UB: deleting a Derived through a Base* without a virtual destructor
```

Deleting through a base-class pointer when the base class has no
`virtual` destructor is UB. The fix: declare the base class
destructor `virtual`. The C++ Core Guidelines rule C.35 is the
canonical reference.

### 6.4 Custom allocators

Any codebase with custom allocators (object pools, slab allocators,
arena allocators) has an additional layer of footguns:

- Returning the allocation to the wrong pool.
- Forgetting to call the destructor before returning the storage.
- Returning the storage to the pool while a `std::unique_ptr` still
  thinks it owns the allocation.
- Concurrent free and allocate on the same pool without
  synchronization.

The C++ Allocator concept (and the `std::pmr::*` polymorphic memory
resources family) standardizes the interface but does not prevent
the underlying defects.

### 6.5 The smart-pointer answer

Modern C++ (C++11+) provides `std::unique_ptr<T>` and `std::shared_ptr<T>`,
which encode ownership in the type system and call the destructor
automatically. The Rule of Zero (§10.3) follows directly:
*if every member is an owning smart pointer or a value type, the
class needs no explicit destructor / copy / move.*

`std::make_unique<T>(args...)` (C++14) and `std::make_shared<T>(args...)`
(C++11) are the preferred allocation forms because they prevent
exception-safety bugs that arise from `new T(args)` inside a
function call (the canonical "leak on argument-evaluation order"
bug; see §10.5).

### 6.6 Sanitizer coverage

- **ASan** catches OOB read/write, UAF, double-free, mismatched
  new/delete, mismatched malloc/free, and use-after-return on
  most platforms. Overhead is ~2x runtime, ~3x memory.
- **MSan** catches uninitialized memory reads. Clang-only.
- The combination of ASan + UBSan + fuzzing has historically caught
  the majority of memory-safety defects in well-fuzzed
  codebases (Chrome, Linux kernel KASAN, OpenSSL).

### 6.7 Auditor's checklist

- Every `new` should pair with `delete` (not `delete[]` or
  `free`); every `new[]` should pair with `delete[]`; every
  `malloc`/`calloc`/`realloc` should pair with `free`.
- Every base class deleted through a base pointer must have a
  `virtual` destructor.
- `realloc` return values must be assigned to a temporary, checked
  for null, and only then assigned back to the owning variable.
- Every raw `new` and `delete` in modern C++ is a candidate point —
  prefer smart pointers.

---

## 7. Stack and buffer overflow primitives

### 7.1 The banned primitives

The following C-library functions have **no safe usage in any
modern codebase**. CERT, OpenBSD, Microsoft SDL, and essentially
every secure-coding standard prohibit them:

- `gets(buf)` — reads from stdin into `buf` with no length limit.
  Removed from C11. The function is universally cited as the
  canonical "should not exist" C library function.
- `strcpy(dst, src)` — copies `src` (including null terminator) to
  `dst` with no length check. OOB write on overlong `src`.
- `strcat(dst, src)` — appends `src` to `dst`. Same defect.
- `sprintf(buf, fmt, ...)` — writes formatted output to `buf` with
  no length limit. OOB write if output exceeds `buf` capacity.
- `vsprintf(buf, fmt, ap)` — varargs variant.
- `scanf("%s", buf)` — reads a whitespace-terminated string with
  no length limit. OOB write.

### 7.2 The `strncpy` trap

`strncpy` is *not* a safe `strcpy`. It has two surprising behaviors:

1. **It does not guarantee null termination.** If the source string
   is longer than the destination size, `strncpy` copies exactly
   `n` characters and *does not append a null terminator*. The
   destination is then not a valid C string.
2. **It null-pads.** If the source string is shorter than the
   destination size, `strncpy` writes null bytes to fill the rest
   of the destination. This is a performance footgun on large
   destinations.

The OpenBSD project's response was `strlcpy` (Miller, USENIX 1999),
which:
- Always null-terminates (unless the destination size is 0).
- Truncates rather than null-pads.
- Returns the *length the source would have been*, allowing the
  caller to detect truncation.

`strlcpy` is in glibc since 2.38 (2023) and in most other libcs.
For older glibc, the OpenBSD source can be vendored.

`snprintf(dst, sizeof(dst), "%s", src)` is a portable alternative
that always null-terminates (assuming size > 0) and returns the
length the result would have been. It is overkill for a simple
copy but is a fine general-purpose replacement.

### 7.3 The fixed-size-local-buffer pattern

```c
void handle(const char *user_input) {
    char buf[256];
    strcpy(buf, user_input);   // stack-based buffer overflow
    process(buf);
}
```

This is the canonical 1988-Morris-worm-shape bug. The fix is
either to use `strlcpy` / `snprintf`, or to compute the actual
length first and reject overlong input.

The CERT STR31-C rule documents the safe forms.

### 7.4 `alloca` and variable-length arrays

`alloca(n)` allocates `n` bytes on the stack and returns a pointer.
If `n` is large (user-controlled), the stack pointer is moved past
the guard page and the program may corrupt memory outside the
stack. This is the **stack clash** family of vulnerabilities
(CVE-2017-1000364 / Qualys "Stack Clash" report).

C99 variable-length arrays (`int arr[n]` where `n` is a runtime
expression) have the same problem. C11 made VLAs optional, and the
C++ standard never adopted them. CERT MEM05-C and the C++ Core
Guidelines both prohibit `alloca` and VLAs in security-relevant
code.

The safe form: `malloc` + `free`, or a fixed maximum size with
explicit rejection of larger inputs.

### 7.5 Mitigations

Stack canaries (Microsoft `/GS`, GCC `-fstack-protector`) place a
random value between the local buffer and the saved frame
pointer / return address. On function return, the canary is
checked; if changed, the program aborts. This is a per-function
overhead of one stack slot and a load+compare on return.

SafeStack (Clang `-fsanitize=safe-stack`) splits the stack into a
safe stack (for control data — return addresses, register
spills) and an unsafe stack (for local arrays and address-taken
locals). Buffer overflows on the unsafe stack cannot reach the
return address.

Both mitigations *raise the bar* but do not eliminate the
vulnerability. An attacker who can read the canary (info leak)
or write past the canary in a precise enough way can still
exploit. See §14 for the broader mitigation landscape.

### 7.6 Auditor's checklist

- Every `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, raw
  `scanf("%s", ...)` is a candidate point.
- Every `strncpy` is a candidate point: is the destination
  guaranteed null-terminated downstream?
- Every fixed-size local array with a `*cpy` or `*cat` into it
  needs the length check enumerated.
- Every `alloca` and VLA is a candidate point — is the size
  bounded?

---

## 8. Format string vulnerabilities

### 8.1 The rule

The `printf` family treats the first string argument as a
**format specifier**, with `%`-escapes that direct it to consume
further arguments. If the format string is **user-controlled**,
the user can:

- Read from the stack: each `%x`, `%s`, `%p` consumes a stack
  slot.
- Read arbitrary memory: `%s` with a stack-leaked pointer
  dereferences and reads as a string until null.
- Write arbitrary memory: `%n` writes the *count of characters
  emitted so far* to the address taken from the next argument
  slot.

`%n` is the load-bearing primitive that turns a format-string
vulnerability into an arbitrary-write — and from there, often
into arbitrary code execution.

### 8.2 The vulnerable forms

```c
printf(user_input);                                    // direct
fprintf(stderr, user_input);                           // direct
snprintf(buf, sizeof(buf), user_input);                // even with size
syslog(LOG_INFO, user_input);                          // syslog family
NSLog(@"%@", [user_input description]);                // Objective-C: log without %@-quoting user data
```

The fix is trivially `printf("%s", user_input);` — always pass user
data through a `%s` and let the format-handling code escape it.

### 8.3 The detection story

GCC and Clang's `-Wformat -Wformat-security` flag non-literal
format strings. The flag has been on by default in most
distributions for over a decade, which is why format-string
vulnerabilities are now rare in new code. The remaining cases
are typically wrappers (`my_log(level, fmt, ...)`) that don't
get the attribute `__attribute__((format(printf, 2, 3)))` and
therefore don't get warned-on at call sites.

Cross-link to `code_review_expertise.md` §3: format strings are
the canonical Mark Dowd candidate-point.

### 8.4 `%n` mitigations

glibc's `FORTIFY_SOURCE` mode rejects `%n` in writable format
strings. Microsoft's CRT (`/Fortify`) does the same. Modern
distros default to this. An attacker who can write the format
string to a read-only mapping (e.g. via a separate vulnerability)
can still exploit, but the common case is mitigated.

### 8.5 The wide-character cousin

`wprintf` and the `wide_char` family have the same vulnerability
shape. The detection story is the same. The exploitation
primitives (`%n`, `%s`) are the same.

### 8.6 Auditor's checklist

- Any `printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`,
  `vfprintf`, `vsprintf`, `vsnprintf`, `syslog`, `err`, `errx`,
  `warn`, `warnx`, with a non-literal first format-string
  argument is a candidate point.
- Wrapper functions (`my_log`, `my_debug`) without the
  `format(printf, ...)` attribute are a meta-candidate point:
  the call sites won't be warned-on.
- `NSLog` / `os_log` in Objective-C: ensure user data is always
  on the right side of a `%@` (or equivalent) format placeholder.

---

## 9. C strings, character encoding, and locale

### 9.1 NUL-terminator semantics

A C string is a sequence of `char` ending in a `'\0'` byte. The
length is *not* stored with the string — every operation that
needs the length must walk the bytes until it finds the
terminator (`strlen`, `strcpy`, `strcat`, `strchr`, `strstr`,
...).

This produces three footgun classes:

1. **Missing terminator → overrun**. A buffer that contains
   bytes but is not null-terminated will cause `strlen` (and
   transitively, every other str* function) to read past the
   end. This is the §7.2 `strncpy` bug class.
2. **Embedded NUL → truncation**. A buffer that contains an
   embedded `'\0'` will appear to `str*` functions as if it
   ended there. If the buffer is supposed to contain
   user-supplied binary data, the embedded NUL silently
   truncates. The Microsoft `\\?\` path-prefix bypass family
   (and the Java / .NET string-vs-bytes encoding-confusion
   family) often hinges on embedded NULs.
3. **Length-prefixed vs. NUL-terminated mismatch**. When a C
   string is converted to or from a length-prefixed
   representation (Pascal-style, network protocol, language
   FFI), the conversion is a candidate point.

### 9.2 Wide strings

The `wchar_t` family (`wcs*` functions, `L"string"` literals) is
parallel to the `char` family with all the same defects, plus a
platform-dependent width: `wchar_t` is 16-bit on Windows, 32-bit
on Unix. Code that round-trips through `wchar_t` is
platform-portable in source but not in binary representation.

UTF-16 surrogate-pair handling on Windows is a particularly
loaded area: a "wide character" is not a Unicode code point
(astral-plane code points are encoded as two `wchar_t` units).
String-length-in-characters vs. string-length-in-units vs.
string-length-in-bytes is a frequent source of subtle bugs.

### 9.3 UTF-8 surprises

UTF-8 is a variable-length encoding: one Unicode code point is
1-4 bytes. C string functions are byte-oriented and treat UTF-8
as a sequence of `char`. Therefore:

- `strlen(utf8)` returns the **byte count**, not the
  code-point count, not the grapheme-cluster count.
- `strncpy(dst, src, n)` may truncate in the middle of a
  multi-byte sequence, leaving the destination with an
  invalid UTF-8 suffix.
- `strchr(utf8, c)` only finds ASCII bytes correctly (bytes
  with the high bit clear); searching for a non-ASCII code
  point requires UTF-8-aware code.

The "UTF-8 normalization → length expansion" footgun (NFC vs.
NFD; some accented characters are one or two code points
depending on normalization form) is the same as in higher-
level languages but compounds in C because the byte count
changes too.

### 9.4 `strtol` / `atoi` / `strtod` parsing

The integer parsing functions have multiple footgun layers:

- `atoi("abc")` returns 0 with no error indication. **Avoid
  `atoi`**: use `strtol` and check `endptr`.
- `strtol` parses as much as it can, sets `errno = ERANGE` on
  overflow but returns `LONG_MAX` / `LONG_MIN`. Always check
  `errno` (after setting `errno = 0` first) and `endptr`.
- The locale-dependent variants (`strtod` in particular)
  respect `LC_NUMERIC`, meaning a locale that uses `,` as the
  decimal separator will parse `"1.5"` as `1` and leave `.5`
  in the unparsed tail. CVE-2019-12290 / GNU libidn2 hits
  this class.
- `strtoull` returns an *unsigned* result even when given a
  negative input: it parses `-1` as `ULLONG_MAX`. Always
  validate the sign separately before calling.

### 9.5 `setlocale` and thread safety

`setlocale` is **not** thread-safe — calling it from one thread
while another thread is in a locale-dependent function is UB.
The C11 `uselocale` + `freelocale` family is thread-local and
safe; library code should prefer it.

### 9.6 Auditor's checklist

- Every `str*` call on a buffer of bytes that may not be
  null-terminated is a candidate point.
- Every parse of user input via `atoi` is a candidate point —
  rewrite to `strtol` with error handling.
- Every locale-dependent parsing call (`strtod`, `scanf` with
  `%f`) on user input is a candidate point.
- Every conversion between byte count and code-point count
  (e.g. UTF-8 truncation, UTF-16 surrogate handling) is a
  candidate point.

---

## 10. C++-specific footguns: lifetime, constructors, and the special members

C++ adds substantial behavioral surface on top of C. This section
covers the C++-only primitives whose default behavior is unsafe.

### 10.1 The constructor-exception trap

```cpp
struct Widget {
    int *data;
    Widget() {
        data = new int[100];
        check_invariant();  // throws std::runtime_error
    }
    ~Widget() { delete[] data; }
};

void f() {
    Widget *w = new Widget;  // throws inside constructor
    // w is never assigned; new[] data is leaked
}
```

If the constructor throws **after** allocating but **before**
completing, the object is **not** fully constructed, and the
destructor is **not** called. The allocated `data` leaks.

The fix is RAII: wrap the allocation in a smart pointer or a
self-owning member.

```cpp
struct Widget {
    std::unique_ptr<int[]> data;
    Widget() : data(std::make_unique<int[]>(100)) {
        check_invariant();  // safe: data is owned by unique_ptr
                            // which is destructed if the throw propagates
    }
};
```

The C++ Core Guidelines C.42 ("If a constructor cannot construct
a valid object, throw an exception") and E.6 ("Use RAII to
prevent leaks") are the canonical references.

### 10.2 The destructor-throws-during-unwinding trap

```cpp
struct Bad {
    ~Bad() { throw std::runtime_error("from dtor"); }
};

void f() {
    Bad b;
    throw std::logic_error("from f");
    // stack unwinds: ~Bad runs, throws, two exceptions in flight,
    // std::terminate() is called, program aborts.
}
```

A destructor that propagates an exception during stack unwinding
causes `std::terminate()` to be called. From C++11 onward,
destructors are **implicitly `noexcept`** — if they throw at
all (not just during unwinding), `std::terminate()` is called
unless the destructor is explicitly declared `noexcept(false)`.

The Core Guidelines C.36 ("A destructor must not fail") is the
canonical reference.

### 10.3 The Rule of Three / Five / Zero

Coined by Marshall Cline (Rule of Three, 1991) and extended by
Howard Hinnant et al. (Rule of Five, ~2010) and R. Martinho
Fernandes (Rule of Zero, ~2012):

- **Rule of Three**: if you define any of {copy constructor,
  copy assignment, destructor}, you almost certainly need to
  define all three. (Because the implicit version of one is
  almost certainly wrong if you needed to define one of the
  others.)
- **Rule of Five**: extending Three with move constructor and
  move assignment, as of C++11. Same logic.
- **Rule of Zero**: prefer to define **none** of the five by
  designing the class so that the compiler-generated defaults
  are correct. Achieved by using smart-pointer or value-type
  members for all owned resources.

Rule of Zero is the canonical modern default. Rule of Five is
required only at the "wrapping a raw resource" boundary.

The defect class: a class that defines a destructor (e.g. to
`free` a `malloc`-ed buffer) but does **not** define copy
constructor / copy assignment will get the compiler-generated
shallow-copy versions, which copy the raw pointer. The first
destructor `free`s the buffer; the second destructor (on the
copy) double-frees. The Rule of Three predicts this.

The fix: delete the copy/move operators (`Widget(const Widget&) = delete;`)
or implement them as deep copies.

### 10.4 Move semantics and moved-from state

C++11 introduced move semantics: `std::move(x)` produces an
rvalue reference, allowing efficient transfer of ownership out
of `x`. After the move, `x` is in a **valid but unspecified
state**. For std types, this means:

- `std::vector` after move: empty, capacity 0 (typically). Safe
  to assign, destruct, or `resize`. Reading
  individual elements is fine (the container *says* it's empty).
- `std::unique_ptr` after move: `nullptr`. Safe.
- `std::string` after move: implementation-defined but typically
  empty.

For user types, the post-move state is whatever the move
constructor / move assignment leaves. The class author is
responsible for documenting it.

The footgun: **using a moved-from object** when the moved-from
state is not what the caller expected. The Core Guidelines
C.64 ("A move operation should move and leave its source in a
valid state") and ES.56 ("Write `std::move()` only when you need
to explicitly move an object to another scope") are the
references.

### 10.5 Argument-evaluation order leak

```cpp
f(std::unique_ptr<Widget>(new Widget), get_data());
```

Pre-C++17, the standard did **not** specify the evaluation
order of function arguments. Permitted interleavings include:

1. `new Widget` (returns a raw pointer)
2. `get_data()` throws
3. The raw pointer is leaked; the `unique_ptr` is never
   constructed.

C++17 tightened the rules so that each *argument expression* is
fully evaluated before the next, but the order between arguments
is still unspecified.

The canonical fix: `f(std::make_unique<Widget>(), get_data());`
— `make_unique` constructs the `unique_ptr` *inside* the
allocation, so there is no temporary raw pointer to leak.

### 10.6 `std::shared_ptr` reference cycles

```cpp
struct Node {
    std::shared_ptr<Node> next;
};

auto a = std::make_shared<Node>();
auto b = std::make_shared<Node>();
a->next = b;
b->next = a;  // cycle: refcounts never reach zero, memory leaks
```

`shared_ptr` uses reference counting. A cycle of `shared_ptr`s
holding each other will never be destroyed.

The fix: break the cycle with `std::weak_ptr` on one side. The
Core Guidelines R.20-R.24 cover smart-pointer ownership.

### 10.7 `dynamic_cast` failure modes

```cpp
Base *p = ...;
Derived *d = dynamic_cast<Derived*>(p);  // returns nullptr on failure
if (!d) { /* handle */ }

Base &r = ...;
Derived &dr = dynamic_cast<Derived&>(r);  // throws std::bad_cast on failure
```

The pointer-form and reference-form failure modes differ. The
pointer form returns `nullptr`; the reference form throws.
Code that uses the pointer form must check the result; code that
uses the reference form must be exception-safe.

`static_cast<Derived*>(p)` does **no runtime check** and is UB
if `p` does not actually point to a `Derived`. It is faster
but unsafe — and the standard does not require a diagnostic.

### 10.8 Auditor's checklist (C++ lifetime)

- Every raw `new` in a constructor body is a candidate point —
  prefer member-init with `std::make_unique`.
- Every destructor that can throw is a candidate point.
- Every class with a user-defined destructor that does not
  also define / delete copy and move operators is a candidate
  point (Rule of Three violation).
- Every `f(std::unique_ptr<T>(new T()), other_arg())` call site
  is a candidate point — prefer `make_unique`.
- Every cycle of `shared_ptr` is a candidate point — break
  with `weak_ptr`.

---

## 11. Modern C++ pitfalls: lambdas, views, and iterator invalidation

### 11.1 Lambda captures and dangling references

```cpp
auto make_counter() {
    int count = 0;
    return [&]() { return ++count; };  // dangling: count is dead at return
}

auto f = make_counter();
f();  // UB: dereferences dangling reference
```

The `[&]` capture is **by reference**. The reference is to a
local variable in `make_counter`, which is destroyed when
`make_counter` returns. The lambda outlives the captured
reference.

The CERT C++ EXP61-CPP rule ("A lambda object must not outlive
any of its reference captured objects") is the canonical
reference.

Variants:
- `[&]` default capture by reference is the most dangerous —
  the developer may not realize what is being captured.
- `[=]` default capture by value is safer but **does not deep-copy
  pointers or references** — a `[=]` capture of a raw pointer
  captures the pointer, not the pointee, and the pointee may
  still be destroyed.
- `[this]` captures the `this` pointer **by value** (the
  pointer; not the object). If the enclosing object is
  destroyed before the lambda is invoked, the lambda has a
  dangling `this`. C++17 added `[*this]` to capture the
  pointed-to object by value.

The Core Guidelines F.52-F.55 cover lambda captures.

### 11.2 `std::string_view` and `std::span`

C++17's `std::string_view` and C++20's `std::span` are
**non-owning views**. They hold a pointer + length and do not
extend the lifetime of the referenced data.

```cpp
std::string_view get_name() {
    std::string s = compute();
    return s;  // dangling: s is destroyed at return
}

std::string_view sv = get_name();  // dangling sv
```

The same defect class as `std::string`'s `c_str()` returning a
dangling pointer when the `std::string` goes out of scope, but
elevated: the entire purpose of `string_view` is to be a
non-owning view, so the bug shape is *intrinsic* to the type.

Best practice (Abseil and the Core Guidelines):
- `string_view` / `span` are **parameter-only** types. Use them
  in function signatures.
- Do **not** store `string_view` / `span` as a member or in a
  container.
- Do **not** return `string_view` / `span` from a function
  unless the caller can prove the underlying data outlives the
  return value.

### 11.3 `std::optional` and `std::variant` failure modes

```cpp
std::optional<int> o;
int x = *o;          // UB: o is empty
int y = o.value();   // throws std::bad_optional_access

std::variant<int, std::string> v = "hello";
int z = std::get<int>(v);          // throws std::bad_variant_access
int *pz = std::get_if<int>(&v);    // returns nullptr; safe
```

`*opt` on an empty `optional` is UB. `opt.value()` throws. The
checked accessor is `opt.value_or(default)`.

`std::get<T>(variant)` on the wrong alternative throws.
`std::get_if<T>(&variant)` returns `nullptr`. The
*pattern-match-ish* alternative is `std::visit`.

### 11.4 Iterator invalidation

A C++ container can invalidate its iterators on mutation. The
exact rules differ per container:

- `std::vector`: any insertion that triggers a reallocation
  invalidates **all** iterators, pointers, and references.
  Insertion that does not reallocate invalidates iterators
  past the insertion point. Erasure invalidates iterators at
  and after the erased element.
- `std::deque`: any insertion or erasure at either end
  invalidates **all** iterators (but pointers and references
  to other elements remain valid).
- `std::list`: only the iterator to the erased element is
  invalidated.
- `std::map` / `std::set` / `std::unordered_map`: insertion
  does not invalidate other iterators; erasure invalidates only
  the iterator to the erased element. For `unordered_*`, rehash
  invalidates all iterators.

The footgun: iterating with `auto it = c.begin(); it != c.end(); ++it`
and modifying `c` inside the loop. Even with `std::list` where
*most* iterators survive, the erased iterator must be replaced
with the return of `c.erase(it)`.

The C++20 `std::erase` / `std::erase_if` free functions provide
a safe interface for the common case.

### 11.5 Range-based-for with temporaries

```cpp
for (auto x : get_strings().split('\n')) { /* ... */ }
// UB pre-C++23: get_strings() temporary destroyed before the
// range expression is fully evaluated; split() holds a dangling reference.
```

The temporary returned from `get_strings()` is destroyed at the
end of the **range-init expression**, *before* the loop body
begins. If the range-init produces a non-owning view of the
temporary, the loop body has a dangling reference.

C++23 fixed this by extending the lifetime of *all* temporaries
in the range expression. Code targeting C++20 or earlier should
materialize the temporary explicitly:

```cpp
auto s = get_strings();
for (auto x : s.split('\n')) { /* safe */ }
```

### 11.6 `constexpr` accidentally non-constexpr

A function marked `constexpr` is **permitted** to be evaluated
at compile time, but is not **required** to be. If the
function is called with non-constant arguments, it is evaluated
at runtime, with no diagnostic. The developer who *intended*
compile-time evaluation may not notice.

C++20's `consteval` enforces compile-time evaluation:
`consteval int f()` is a compile error if `f` is called with
runtime arguments.

The footgun is mainly a performance / clarity issue (no security
impact in the usual case), but is included here because it is a
frequent source of "this is supposed to be a compile-time
check, why isn't it firing?" questions.

### 11.7 Auditor's checklist (modern C++)

- Every `[&]` capture is a candidate point: prove the captured
  references outlive the lambda.
- Every `string_view` / `span` stored as a member or returned
  from a function is a candidate point.
- Every `*opt` or `opt.value()` is a candidate point —
  consider `value_or` or `get_if`.
- Every container mutation inside a loop over its iterators is
  a candidate point.
- Every range-based-for over a temporary expression is a
  candidate point pre-C++23.

---

## 12. Concurrency and the memory model

### 12.1 The C++11+ memory model

Before C++11, the language standard had no memory model: the
program's behavior under concurrent access was outside the
standard's scope. C++11 introduced `std::atomic<T>`, the
`std::memory_order` enum, and the *data race* rule: **two
concurrent accesses to the same memory location, at least one
of which is a write, both unsynchronized, both non-atomic, is
a data race, which is undefined behavior.**

This is the load-bearing rule for concurrent C++. Every
shared-state access between threads must be either:

- Through a `std::atomic<T>`, or
- Inside a critical section protected by a mutex (which
  establishes happens-before via the mutex's acquire/release
  semantics), or
- Synchronized through some other mechanism that establishes
  happens-before (`std::future`, channel-like primitives, or
  user-defined synchronization).

A data race is **not** "the program might produce a torn read."
It is **undefined behavior**, meaning the compiler is permitted
to assume it cannot happen and optimize accordingly. The same
§2.2 logic that produces signed-overflow elisions produces
data-race-induced optimization surprises.

### 12.2 `std::memory_order_*`

The six orderings (per `std::memory_order`):

- `memory_order_relaxed`: only atomicity, no ordering.
- `memory_order_consume`: deprecated in practice, treat as
  `acquire`.
- `memory_order_acquire`: a load-acquire — no later operations
  in this thread can be reordered before this load.
- `memory_order_release`: a store-release — no earlier operations
  in this thread can be reordered after this store.
- `memory_order_acq_rel`: read-modify-write that is both an
  acquire and a release.
- `memory_order_seq_cst`: sequential consistency — all
  `seq_cst` operations in the program have a single total
  order. **Default** for all `std::atomic` operations.

The footgun: developers see `memory_order_relaxed` in
performance-tuning literature and use it without understanding
the implied ordering. A relaxed store on a flag, paired with a
relaxed load on the reader, gives **no** happens-before
relationship — the reader can observe the flag set while the
data being signaled is not yet visible.

The C++ Core Guidelines CP.21 ("Use `std::lock()` ... to
acquire multiple `mutex`es") and CP.20 ("Use RAII, never plain
`lock()`/`unlock()`") cover the high-level discipline.

### 12.3 `volatile` is not a synchronization primitive

In C and C++, `volatile` means "the value of this object can
change in ways the compiler cannot predict (memory-mapped
hardware register, signal handler, longjmp)." It does **not**
provide:

- Atomicity (a `volatile int` read may tear).
- Memory ordering (a `volatile` write does not establish
  happens-before).
- Thread synchronization (a `volatile` flag is not a mutex).

This is **different from Java**, where `volatile` does provide
happens-before semantics. Code ported from Java or written by
Java-experienced engineers is a candidate point.

Use `std::atomic<T>` for synchronization. Use `volatile` only
for memory-mapped IO and `setjmp`/`longjmp` correctness.

Cross-link to `race_conditions_concurrency_expertise.md`.

### 12.4 Mutex patterns and pitfalls

The C++ Core Guidelines CP family cover the discipline. The
canonical footguns:

- **Forgetting to unlock**: `m.lock(); /* throw */; m.unlock();`
  leaves the mutex held. Use `std::lock_guard<std::mutex>` or
  `std::unique_lock`.
- **Locking in inconsistent order**: thread A locks `m1` then
  `m2`; thread B locks `m2` then `m1`. Deadlock. Use
  `std::lock(m1, m2)` or `std::scoped_lock(m1, m2)` (C++17)
  to acquire multiple mutexes atomically.
- **Holding a lock across a callback**: the callback may
  re-enter the locked region (recursive lock) or call back
  into a different lock (deadlock). Avoid holding locks across
  user-provided callbacks.
- **Re-locking a non-recursive mutex**: deadlocks. Use
  `std::recursive_mutex` only when truly needed.

### 12.5 Spurious wakeups and condition variables

`std::condition_variable::wait` is allowed to return *without*
the predicate becoming true (spurious wakeup). The canonical
pattern:

```cpp
std::unique_lock lk(m);
cv.wait(lk, [&]{ return ready; });  // checks predicate; loops on spurious wakeup
```

The `wait(lock, predicate)` overload internally re-checks the
predicate and re-waits if spuriously woken. The naked
`wait(lock)` overload does not, and must be wrapped in a
manual loop.

### 12.6 `thread_local` initialization order

`thread_local` variables are initialized on first use per
thread. The initialization order across `thread_local`
variables is the order of definition within a thread, but
across threads is unsynchronized. Initialization that has side
effects on shared state must be synchronized explicitly.

### 12.7 Signal handlers and async-signal-safety

A signal handler in C/C++ can be invoked at any point in the
program's execution, including in the middle of a `malloc` or
`printf` call. The set of functions that may be called from a
signal handler is the **async-signal-safe** set (POSIX
`signal-safety(7)`). Calling a non-async-signal-safe function
from a signal handler is UB.

The async-signal-safe set is narrow: `_exit`, `write`,
`sigaction`, and a few others. **`malloc`, `free`, `printf`,
`fprintf`, `pthread_*` are all unsafe.**

The fix: signal handlers should set a `sig_atomic_t volatile`
flag and return. The main loop checks the flag.

### 12.8 Auditor's checklist (concurrency)

- Every shared variable not declared `std::atomic` and not
  protected by a mutex is a candidate point for data-race UB.
- Every `memory_order_relaxed` use is a candidate point.
- Every `volatile` in a synchronization role is a candidate
  point — replace with `std::atomic`.
- Every multi-mutex lock without `std::scoped_lock` is a
  candidate point for deadlock.
- Every signal handler is a candidate point — does it call
  only async-signal-safe functions?

---

## 13. Build system, ABI, and ODR footguns

### 13.1 The One Definition Rule (ODR)

The ODR says: every non-inline function, variable, type, and
template has **exactly one** definition across the entire
program. Multiple definitions are UB and the compiler is **not
required to diagnose**. Linkers may diagnose duplicate
definitions of external-linkage functions (gold and lld do;
older `ld` may not).

The footgun: a header defines an `inline` function (or a
template), and two translation units include the header with
different macro definitions in scope. The compiler emits two
different function bodies under the same name; the linker
picks one. The other translation unit's call sites silently
get the *wrong* body.

The Linux kernel has historically been bitten by this in the
`CONFIG_*` macro family: a struct definition depends on a
config flag, and a single TU compiled with the wrong flag
corrupts every TU it links against. The fix: macros that
affect ABI should be in the build system, not per-TU.

### 13.2 Header-only library version skew

A header-only library (e.g. Boost.Hana, fmtlib in header-only
mode) inlines code into every TU that includes it. If two TUs
include different versions of the same header-only library,
they emit inconsistent inline functions with the same mangled
name. The linker picks one; the other is silently wrong.

Common in CMake projects that vendor headers vs. system
headers without aligning the versions. The fix: pin one
version system-wide, or use ODR-safe library design (no
external linkage, no member-template ODR surface).

### 13.3 `_GLIBCXX_USE_CXX11_ABI` and ABI skew

GCC 5 introduced a new `std::string` ABI (with the
`std::__cxx11::basic_string` name) and a macro
`_GLIBCXX_USE_CXX11_ABI` to select between old and new. A
library built with the old ABI cannot interoperate with code
built with the new ABI — passing a `std::string` across the
boundary corrupts memory.

This is the most common "everything links, nothing runs" defect
in C++ codebases that mix vendored libraries with different
compilers. The fix is to align the macro across all build
units; the long-term fix is to never pass STL types across an
ABI boundary (use C-compatible interfaces at boundaries).

### 13.4 `-fvisibility=default`

The default symbol visibility on most ELF platforms is `default`
(everything is exported). For a shared library, this means
internal helper functions are visible to other libraries and
to ld.so's symbol resolution. Two libraries with conflicting
internal `helper` functions will pick one at link time and
silently use it.

The fix: build with `-fvisibility=hidden` and explicitly
annotate the exported API with `__attribute__((visibility("default")))`
(or, on Windows, `__declspec(dllexport)`). The Core Guidelines
SF.20 ("Use namespaces to express logical structure") and the
Itanium C++ ABI documentation are the references.

### 13.5 Static linking and symbol collision

A program that statically links two libraries that themselves
embed the same dependency (e.g. zlib) gets two copies of zlib
in the binary. Symbol resolution picks one; the other is dead
code. If the two copies have different versions, the one
picked may be wrong for one of the call paths. CVE-2022-23218
(glibc `svcunix_create`) had a related shape.

### 13.6 Auditor's checklist (build)

- Every macro that controls a struct layout, function inline
  body, or class template is a build-system candidate point.
- Every `-fvisibility=default` build is a candidate point —
  prefer `hidden`.
- Every ABI macro (`_GLIBCXX_USE_CXX11_ABI`, `_ITERATOR_DEBUG_LEVEL`,
  MSVC `/std:c++NN` mismatch) across linked artifacts is a
  candidate point.
- Every statically-linked binary that includes both directly
  and transitively a common dependency is a candidate point.

---

## 14. The mitigation landscape (defense in depth)

Mitigations do not eliminate the underlying footguns; they raise
the cost of exploitation. The auditor should understand which
mitigations apply to which bug classes.

### 14.1 ASLR and PIE

- **ASLR** (Address Space Layout Randomization) randomizes the
  base addresses of the stack, heap, and shared libraries on
  each process launch.
- **PIE** (Position-Independent Executable) extends ASLR to the
  main binary itself.

Effective against fixed-address exploitation primitives (ROP
gadgets at known addresses). Bypassed by **information
leaks** that reveal a single address from any randomized
region — once one address is known, the rest of that region's
layout is determined relative to it. Linux defaults to ASLR+PIE
since the early 2010s; Windows defaults to ASLR via `/DYNAMICBASE`
and `/HIGHENTROPYVA`.

### 14.2 DEP / W^X

**Data Execution Prevention** (Windows) / **W^X** (BSDs):
memory pages are either writable or executable, never both.
Prevents the classic "shellcode-on-stack-then-jump" attack.
Bypassed by **return-oriented programming** (ROP) and other
code-reuse attacks.

### 14.3 Stack canaries

`-fstack-protector` and variants (`-fstack-protector-strong`,
`-fstack-protector-all`) emit a random canary value between the
local buffer and the saved frame pointer / return address.
Checked on function return; mismatch triggers abort.

Bypassed by:
- Information leak revealing the canary value.
- Direct overwrite of the return address (e.g. heap overflow
  into stack via clobbered function pointer).
- Stack-pointer-relative writes that skip the canary (e.g.
  format-string `%n` write).

### 14.4 Control-Flow Integrity (CFI)

CFI restricts indirect control transfers (function pointer
calls, virtual calls, returns) to a set of valid targets
determined by static analysis. Clang's `-fsanitize=cfi` and
MSVC's `/guard:cf` are the canonical implementations.

Effective against arbitrary-jump primitives. Bypassed by:
- Data-only attacks that don't transfer control.
- Type-confused calls within the allowed target set.
- Coarse-grained CFI policies (older implementations) that
  allow too many targets.

### 14.5 ARM PAC (Pointer Authentication Code)

PAC adds a cryptographic signature to the unused high bits of
a pointer. The signature is computed from the pointer value, a
context (e.g. the stack pointer for a return address), and a
secret key. Before using the pointer, the signature is
verified; mismatch produces an exception.

Effective against:
- Return-address corruption (return-PAC).
- Indirect-call corruption (call-PAC).
- Generic pointer corruption (data-PAC).

Bypassed by **signing oracles** — code that signs an
attacker-controlled value with the legitimate key.
Apple's ARM64e (since A12) and Linux on Armv8.3+ implement PAC.

Cross-link to `hardware_side_channels_expertise.md`.

### 14.6 ARM MTE (Memory Tagging Extension)

MTE associates a 4-bit tag with each 16-byte memory granule and
encodes the same tag in the high bits of pointers. Memory
accesses check that the pointer tag matches the memory tag;
mismatch produces an exception.

Effective against:
- Buffer overflows that cross tagged-granule boundaries (likely
  to hit a different tag).
- Use-after-free (the freed region is re-tagged).

Bypassed by tag collisions (4-bit tag → 1/16 chance of
collision per random pointer). MTE is most useful as a
**probabilistic** defense: an attacker needing multiple
successful exploits has compounded probability of detection.

Apple's iPhone 17 Pro (2025, A19 Pro and onward) shipped
Memory Integrity Enforcement (MIE), which combines MTE with
PAC and other primitives.

### 14.7 Intel CET

**Control-flow Enforcement Technology**: shadow stack
(hardware-maintained alongside the regular stack, contains
return addresses; mismatch on return triggers exception) +
indirect-branch tracking (CALL targets must have an `ENDBR`
instruction; non-`ENDBR` targets fault).

Effective against return-address corruption and ROP. Shipping
in Intel Tiger Lake (2020) and onward; Windows 10 21H1+ and
Linux 5.18+ support it.

### 14.8 The reality

Every mitigation listed above can be bypassed in isolation
given the right primitives. They raise the bar but do not
eliminate exploitation. The aggregate effect of ASLR+PIE+DEP
+canaries+CFI+PAC+MTE+CET is that a successful exploit often
requires:

- Two or more memory-corruption primitives (one to leak, one
  to write).
- Avoiding crashes that would be detected by sanitizers in
  fuzz-tested codebases.
- Choosing a target that hasn't been hardened with
  language-level memory safety (CHERI capabilities,
  `-fbounds-safety`, or rewriting to a memory-safe language).

This is why the strategic answer (NSA / CISA / ONCD) is **memory-
safe languages**, not just better C/C++ mitigations. The
mitigations are necessary; they are not sufficient.

---

## 15. Detection patterns

### 15.1 Semgrep / pattern-matcher coverage

The banned-primitive set is well-suited to pattern matching:

```yaml
# Conceptual sketch; see semgrep_rule_authoring.md for full form.
rules:
  - id: c-banned-strcpy
    pattern-either:
      - pattern: strcpy(...)
      - pattern: strcat(...)
      - pattern: gets(...)
      - pattern: sprintf(...)
      - pattern: vsprintf(...)
    message: "Banned primitive: use strlcpy / snprintf / equivalent."
    severity: ERROR
    languages: [c, cpp]
```

Additional patterns to express:

- `printf($USER_INPUT, ...)` with non-literal first argument.
- `new $T` / `delete $P` (raw new/delete; suggest smart pointers).
- `malloc(...)` without paired check for NULL return.
- `strncpy($DST, $SRC, $N)` (always-truncating; suggest strlcpy).
- `*(($T *)&$VAR)` (strict-aliasing violation; suggest memcpy /
  bit_cast).
- `[&]` lambda captures (review for lifetime).
- `std::string_view` / `std::span` returned from a function
  (review for lifetime).

Cross-link to `semgrep_rule_authoring.md` for the precision-first
authoring discipline.

### 15.2 Sanitizers (LLVM family)

| Sanitizer | What it catches | Overhead | Mode |
|---|---|---|---|
| ASan | OOB read/write, UAF, double-free, mismatched new/delete | ~2x runtime, ~3x memory | Build-time |
| UBSan | Most undefined behaviors enumerated in the standard | ~10-50% | Build-time |
| MSan | Reads of uninitialized memory | ~3x runtime | Build-time (Clang only) |
| TSan | Data races | ~5-15x runtime | Build-time |
| LSan | Memory leaks | Low (ASan-integrated) | Build-time |
| HWASan | OOB / UAF using ARM MTE-style tagging | ~2x | Build-time (ARM64) |

ASan + UBSan + a coverage-guided fuzzer (libFuzzer, AFL++,
honggfuzz) is the *standard* dynamic-analysis configuration
for new C/C++ code. The Chrome team, the Linux kernel
(syzkaller), OpenSSL, ICU, libpng, and effectively every
mature open-source C/C++ project run this pipeline
continuously.

Cross-link to `fuzzing_discipline_expertise.md` §2.

### 15.3 Static analyzers

| Analyzer | Strength |
|---|---|
| Clang Static Analyzer (scan-build) | Free; integrated with Clang; symbolic execution; catches null-deref, use-after-free, memory leak |
| CodeQL (GitHub) | Free for OSS; data-flow; semantic queries; deep library support |
| Coverity | Commercial; the institutional baseline for C/C++ audit |
| PVS-Studio | Commercial; pattern-based; large rule catalog |
| Klocwork | Commercial; deep dataflow |
| Frama-C + TIS-Interpreter | Sound; formal-methods-grade; high annotation cost |
| Cppcheck | Free; lightweight; pattern-based |

The unsound analyzers (Coverity, PVS, CodeQL, Cppcheck) are
practical for industrial codebases. The sound analyzers
(Frama-C, TIS-Interpreter) are used in safety-critical
contexts (aerospace, automotive) where the cost of unsoundness
is greater than the cost of annotation.

### 15.4 Hardware-assisted detection

- **ASan + HWASan**: software tagging.
- **MTE**: hardware tagging on ARM (production on Pixel 8+,
  iPhone 15 Pro+).
- **CHERI**: capability-based; full spatial and temporal memory
  safety with source-level near-compatibility (Morello,
  CHERIoT).
- **Intel MPX** (deprecated 2018): bounds-checking; ineffective
  in practice.

### 15.5 Compiler warnings

The Microsoft SDL banned-function list and the GCC/Clang flag
sets are the canonical baselines:

```
-Wall -Wextra -Wpedantic
-Wshadow -Wconversion -Wsign-conversion
-Wformat=2 -Wformat-security
-Wuninitialized -Wmaybe-uninitialized
-Wnull-dereference
-Wcast-align -Wcast-qual
-Wold-style-cast (C++)
-Werror=implicit-function-declaration
```

A new C/C++ codebase should compile clean under `-Wall -Wextra
-Wpedantic -Werror`. Existing codebases should adopt
incrementally per-file.

### 15.6 Cross-link to detection-engineering

The `detection_engineering_expertise.md` covers the broader
strategy of converting these patterns into rules. The
`semgrep_rule_authoring.md` covers the rule-authoring
discipline (precision-first, corpus-validated). The
`fuzzing_discipline_expertise.md` covers the fuzzer harness
and corpus discipline.

---

## 16. Defensive checklist and variant-analysis frontier

### 16.1 The 20-item review checklist

When reviewing a C or C++ patch, run through each of these
candidate-point patterns:

1. **Banned C library functions**: `gets`, `strcpy`, `strcat`,
   `sprintf`, `vsprintf`, `scanf("%s", ...)`. Block.
2. **Format-string call sites**: non-literal first arg to any
   `printf`-family call. Block.
3. **Signed integer arithmetic on untrusted input**: review for
   overflow; prefer `__builtin_*_overflow` or `<stdckdint.h>`.
4. **Pointer-cast type punning**: `*(T*)&x` or `(T*)p`. Rewrite
   to `memcpy` or `std::bit_cast`.
5. **`strncpy` / `wcsncpy`**: replace with `strlcpy` / `snprintf`
   / `wcslcpy`.
6. **Fixed-size local buffer with user-controlled input**:
   prove the length check is correct, or reject overlong input.
7. **`alloca` / VLA with user-controlled size**: replace with
   `malloc` or fixed-size.
8. **`realloc` return value handling**: must be `tmp = realloc(...);
   if (tmp) p = tmp;`.
9. **Raw `new` / `delete` (C++)**: replace with `make_unique` /
   `make_shared`.
10. **Polymorphic deletion through base pointer**: base class
    has `virtual` destructor.
11. **Rule of Three / Five violations**: class with destructor
    must define / delete copy and move.
12. **`[&]` lambda captures**: prove the captured references
    outlive the lambda.
13. **`std::string_view` / `std::span` lifetime**: parameter-only;
    no member storage; no return.
14. **`*opt` / `std::get<T>` / `std::variant` access**: use
    `value_or` / `get_if` / `visit`.
15. **Iterator invalidation in loops**: use `c.erase(it)` return
    or `std::erase_if`.
16. **Data races on shared state**: every non-atomic shared
    variable must be mutex-protected.
17. **`memory_order_relaxed`**: review with high suspicion.
18. **`volatile` as synchronization**: replace with `std::atomic`.
19. **Signal handler safety**: only async-signal-safe calls;
    set `sig_atomic_t volatile` flag, return.
20. **ODR / ABI hygiene**: macros that change struct layout
    are in the build system, not per-TU; `-fvisibility=hidden`
    on shared libraries.

### 16.2 Variant analysis

Variant analysis (Mark Dowd, TAOSSA chapter 4) is the
practice of: given a known bug, search the codebase for the
same primitive used in the same way, anticipating that the
same defect class will recur. For C/C++ specifically:

- A `strcpy` bug in one parser is almost always paired with
  more `strcpy` bugs in other parsers — review the entire
  parser family.
- A signed-overflow bug in one length-computation is almost
  always paired with similar bugs in other length-computations
  — search for the same arithmetic shape.
- A UAF in one teardown sequence is almost always paired with
  similar UAFs in other teardown sequences — search for the
  same destructor-callback shape.
- An iterator-invalidation bug in one `vector::erase` loop is
  almost always paired with similar bugs elsewhere.

Cross-link to `code_review_expertise.md` §2 (the Dowd
candidate-point pattern) and `vulnerability_research_methodology_expertise.md`
(variant-analysis tooling and corpus mining).

### 16.3 The memory-safe-language frontier

The strategic answer to C/C++ behavioral footguns is to move
to a memory-safe language for new code:

- **Rust** for systems code (kernel, OS, drivers, network stacks,
  parsers). The Linux kernel admits Rust modules; the Android
  platform team has documented zero memory-safety CVEs in new
  Rust code despite millions of lines shipped.
- **Go** for application services, network daemons, CLI tools.
- **Swift** for Apple-platform applications.
- **C#** / **Kotlin** / **TypeScript** for application-layer
  code on .NET / JVM / browser respectively.

For existing C/C++ code that cannot be rewritten, the
intermediate options are:

- **CHERI** (Morello, CHERIoT): hardware-augmented C/C++ with
  full spatial / temporal memory safety. ~0.026% source-line
  modification rate documented in the Cambridge corpus study.
- **`-fbounds-safety`** (Clang, Apple-led): C dialect with
  bounded pointers. Shipping in Apple toolchains, upstreaming
  to Clang.
- **C++ Safety Profiles** (Stroustrup, Sutter): the C++ committee's
  in-flight answer to the memory-safety pressure. Aims to give
  a subset of C++ machine-checkable memory safety. (Carbon and
  Cpp2 / cppfront are out-of-committee alternatives.)

Cross-link to `firmware_embedded_security.md` (where the
rewrite frontier is most constrained), `linux_kernel_exploitation_expertise.md`
(where Rust-in-kernel is the live debate), and
`macos_memory_corruption_investigation.md` (for the Apple-side
PAC/MTE/MIE story).

### 16.4 The triage-cost calculus

Not every C/C++ codebase justifies a rewrite. The triage
question is: **what is the marginal cost of a memory-safety
defect in this codebase?** If the answer is "shipped to
internet-facing infrastructure that attackers actively
target," the marginal cost is high enough to justify
sanitizer + fuzzer + static analyzer + hardware mitigations,
and likely a partial rewrite for the most-exposed surfaces.
If the answer is "internal tool with a low-trust threat model,"
the marginal cost is lower and the development cost of a
rewrite is harder to justify.

This calculus is the same as in the C# / Java / Python footgun
docs: the *existence* of a footgun does not automatically
justify any particular mitigation. The auditor's job is to
weigh the marginal cost against the alternatives.

---

## 17. References

### Books

- Seacord, R. C. *Secure Coding in C and C++*, 2nd ed.,
  Addison-Wesley, 2013.
- Seacord, R. C. *The CERT C Coding Standard*, 2nd ed.,
  Addison-Wesley, 2014.
- Dowd, M., McDonald, J., Schuh, J. *The Art of Software
  Security Assessment*, Addison-Wesley, 2006.
- Stroustrup, B. *The Design and Evolution of C++*,
  Addison-Wesley, 1994.
- Stroustrup, B. *The C++ Programming Language*, 4th ed.,
  Addison-Wesley, 2013.
- Sutter, H., Alexandrescu, A. *C++ Coding Standards*,
  Addison-Wesley, 2004.
- Sutter, H. *Exceptional C++*, *More Exceptional C++*,
  *Exceptional C++ Style*, Addison-Wesley, 1999-2005.
- Meyers, S. *Effective Modern C++*, O'Reilly, 2014.
- Kernighan, B. W., Ritchie, D. M. *The C Programming
  Language*, 2nd ed., Prentice Hall, 1988.

### Standards and guidelines

- ISO/IEC 9899:2018 (C17 / C18).
- ISO/IEC 9899:2024 (C23 — mandates two's-complement signed
  integers; adds `<stdckdint.h>` checked arithmetic).
- ISO/IEC 14882:2020 (C++20), 2024 (C++23).
- CERT C Coding Standard,
  https://wiki.sei.cmu.edu/confluence/display/c
- CERT C++ Coding Standard,
  https://wiki.sei.cmu.edu/confluence/display/cplusplus
- C++ Core Guidelines (Stroustrup, Sutter),
  https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines
- MISRA C:2012 (industrial-grade subset for embedded /
  safety-critical).

### Foundational blog series

- Regehr, J. "A Guide to Undefined Behavior in C and C++,"
  Parts 1-3, https://blog.regehr.org/archives/213,
  https://blog.regehr.org/archives/226,
  https://blog.regehr.org/archives/232
- Regehr, J. "It's Time to Get Serious About Exploiting
  Undefined Behavior," https://blog.regehr.org/archives/761
- Regehr, J. "Type Punning, Strict Aliasing, and Optimization,"
  https://blog.regehr.org/archives/959
- Lattner, C. "What Every C Programmer Should Know About
  Undefined Behavior," Parts 1-3,
  https://blog.llvm.org/2011/05/what-every-c-programmer-should-know.html

### CERT rules referenced

- INT32-C — Ensure that operations on signed integers do not
  result in overflow,
  https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow
- STR31-C — Guarantee that storage for strings has sufficient
  space for character data and the null terminator.
- MEM05-C — Avoid large stack allocations (alloca / VLAs).
- EXP61-CPP — A lambda object must not outlive any of its
  reference captured objects,
  https://wiki.sei.cmu.edu/confluence/display/cplusplus/EXP61-CPP.+A+lambda+object+must+not+outlive+any+of+its+reference+captured+objects

### Strings, formats, and parsing

- Miller, T. C., de Raadt, T. "strlcpy and strlcat — consistent,
  safe, string copy and concatenation,"
  https://www.millert.dev/papers/strlcpy/
- OWASP, "Format String Attack,"
  https://owasp.org/www-community/attacks/Format_string_attack

### Sanitizers

- Serebryany, K. et al. "AddressSanitizer: A Fast Address
  Sanity Checker," USENIX ATC 2012.
- Stepanov, E., Serebryany, K. "MemorySanitizer: Fast Detector
  of Uninitialized Memory Use in C++."
- Clang AddressSanitizer documentation,
  https://clang.llvm.org/docs/AddressSanitizer.html
- Google sanitizers repository,
  https://github.com/google/sanitizers

### Mitigations

- Linux Kernel "Stack Clash" (Qualys, 2017),
  https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
- Microsoft "Control Flow Guard,"
  https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard
- Apple "Memory Integrity Enforcement,"
  https://security.apple.com/blog/memory-integrity-enforcement/
- Arm Memory Tagging Extension whitepaper,
  https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Arm_Memory_Tagging_Extension_Whitepaper.pdf
- Intel Control-Flow Enforcement Technology specification.

### CHERI and the memory-safety frontier

- Watson, R. et al. "CHERI: Hardware-Enabled C/C++ Memory
  Protection at Scale," IEEE S&P 2024,
  https://www.cl.cam.ac.uk/research/security/ctsrd/pdfs/20240419-ieeesp-cheri-memory-safety.pdf
- CHERI project home,
  https://www.cl.cam.ac.uk/research/security/ctsrd/cheri/
- CHERIoT (Microsoft),
  https://www.microsoft.com/en-us/research/project/cheriot/

### Memory-safe-language pressure

- NSA Cybersecurity Information Sheet, "Software Memory
  Safety," 2022.
- CISA, "Product Security Bad Practices," 2024 (flags
  memory-unsafe languages for critical infrastructure).
- ONCD, "Back to the Building Blocks" white paper, 2024.
- Android security retrospective, "Memory Safe Languages in
  Android 13,"
  https://security.googleblog.com/2022/12/memory-safe-languages-in-android-13.html

### Audit corpora and exploit research

- Project Zero blog, https://googleprojectzero.blogspot.com/
- Trail of Bits "Awesome CodeQL,"
  https://github.com/trailofbits/awesome-codeql

### Tooling

- Clang Static Analyzer, https://clang-analyzer.llvm.org/
- CodeQL, https://codeql.github.com/
- Cppcheck, https://cppcheck.sourceforge.io/
- Frama-C, https://www.frama-c.com/
- TIS-Interpreter, https://trust-in-soft.com/tis-interpreter/
- PVS-Studio, https://pvs-studio.com/
- libFuzzer, https://llvm.org/docs/LibFuzzer.html
- AFL++, https://aflplus.plus/

---

## Coda — placement in the behavioral-footgun corpus

This is the seventh and final language doc in the **language-
specific behavioral footguns** class (after C#, Java, Python,
JavaScript / Node, PHP, Ruby). The placement is deliberate: C
and C++ have more behavioral surface than the other six combined,
and most of that surface is **load-bearing** (the language is
used precisely because the developer wants control that other
languages refuse to give). The footgun count is not a
quality defect of C and C++; it is the price of the design
goals.

The cross-cutting observation across all seven docs: every
language has a small number of primitives whose default
behavior is unsafe and whose name does not signal that. The
auditor's job is to enumerate those primitives, know what
they actually do, and treat each call site as a candidate point
(Mark Dowd sense) until proven safe. The compiler will not save
you. The type system will not save you. The developer-time
linter helps but does not exhaust the audit surface. The
sanitizers help dynamically but only on inputs the test suite
or fuzzer reaches. The hardware mitigations raise the bar but
do not eliminate the underlying defect.

The strategic answer is **memory-safe languages for new code**
plus **defense in depth for legacy code**. The tactical answer
is this checklist, applied at every C/C++ patch boundary.

The sibling doc on Rust behavioral footguns is the natural
companion: Rust eliminates the bulk of the C/C++ footguns at the
type-system level but introduces its own set (Pin, Send/Sync
auto-traits, unsafe-block contracts, Drop panic, async
cancellation). See `rust_footguns_expertise.md` (when authored).
