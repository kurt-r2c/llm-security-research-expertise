# Swift Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Apple Swift core / language-steering-group engineers, the JavaScriptCore performance and exploitation researchers whose work intersects Swift via the WebKit / Obj-C surface, and the institutional iOS-audit corpus that catalogs Swift-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is part of the
> **language-specific behavioral footguns** class — cataloguing primitives whose
> *default behavior* in a specific language ecosystem is unsafe, distinct from
> cross-language bug-class docs (deserialization, cryptography, race conditions,
> CI/CD supply chain, SSRF) that cover attack surface by class rather than by
> language. The 2024-2026 load-bearing updates: Swift 6's strict-concurrency
> language mode shipping data-race detection at compile time (the Holly Borla /
> Doug Gregor / John McCall multi-year push, completed for the Swift 6.0
> release); noncopyable types (`~Copyable`) and parameter ownership modifiers
> (`borrowing` / `consuming`) stabilized through Swift 6 (SE-0377); Embedded
> Swift landing as a supported target (SE-0405 through SE-0407); Vapor 4.x and
> Hummingbird 2.x stabilizing as server-side Swift web frameworks; Swift
> Package Manager build plugins maturing as a sandboxed-but-trust-the-package
> surface (SE-0303); CryptoKit's continued role as the modern cryptographic
> API with `Insecure.MD5` / `Insecure.SHA1` namespaced into a danger-
> signaling type hierarchy; the running stream of WKWebView / JavaScriptCore
> advisories against iOS / iPadOS / macOS that demonstrate the Swift / Obj-C /
> JS boundary as a real exploitation surface (the Samuel Groß "saelo"
> research corpus is the canonical reference for what attackers do once they
> reach JavaScriptCore through a Swift-hosted `WKWebView`).
>
> **Researchers:**
> - **Chris Lattner** — original creator of Swift (development started at
>   Apple 2010, public release WWDC 2014); also creator of LLVM, Clang, and
>   the Mojo language (Modular AI, 2022). Inaugural 2010 ACM SIGPLAN
>   Programming Languages Software Award for LLVM. Swift design rationale —
>   safety by default with carefully named unsafe escapes (`Unsafe*Pointer`,
>   `unsafeBitCast`, `unowned(unsafe)`, `nonisolated(unsafe)`), value-type-
>   first composition, protocol-oriented programming, Obj-C interop without
>   a runtime tax — is in his early WWDC keynotes and the swift.org design
>   essays.
> - **John McCall** (rjmccall) — Apple Senior Software Engineer; Chair of
>   the Swift Language Steering Group; code owner for AST → SIL lowering,
>   SIL → LLVM IR lowering, parts of the ABI and runtime, and the value-
>   ownership model. Review Manager for SE-0377 (parameter ownership
>   modifiers, Swift 5.9); driving the move toward explicit value ownership
>   (`borrowing`, `consuming`, noncopyable types).
> - **Joe Groff** (jckarter) — Apple Swift core team member from the
>   beginning; one of the original five engineers (with Chris Lattner, Doug
>   Gregor, John McCall, and Ted Kremenek) who started Swift in 2010. Major
>   contributions to type metadata / runtime reflection, the generics
>   implementation, and Swift 1.x → 5.x evolution proposals.
> - **Doug Gregor** (DougGregor) — Apple Distinguished Engineer; founding
>   member of the Swift Core Team; active on the Language Steering Group.
>   Author of numerous Swift evolution proposals across generics, concurrency,
>   and macros. The douggregor.net "Doug's Compiler Corner" blog is one of
>   the more candid sources for Apple-internal Swift design conversations.
> - **Holly Borla** — manages the Swift language team at Apple; primary
>   architect of the Swift 6 strict-concurrency rollout. Co-author on
>   SE-0412 (strict concurrency for global variables), SE-0414 (region-based
>   isolation), and the broader Sendable / actor-isolation surface that
>   makes Swift 6's compile-time data-race detection work.
> - **Karoy Lorentey** (lorentey) — Apple Swift standard library engineer;
>   primary contributor to `String` / `String.Index` performance and
>   Unicode-correctness work. Author of SE-0445 (Swift 6.1 string-index
>   printing). Maintains the Swift Collections package
>   (`OrderedDictionary`, `Deque`, `Heap`).
> - **Filip Pizlo** (filpizlo) — formerly Manager of the JavaScriptCore
>   team at Apple (Feb 2017 - Feb 2022); author of JSC's LLInt, FTL JIT,
>   B3 compiler backend, Riptide GC, and libpas. While not on the Swift
>   team, JSC is the *other side* of every `WKWebView.evaluateJavaScript`
>   call. The Pizlo corpus at webkit.org/blog and filpizlo.com is the
>   canonical reference for the JS engine that Swift apps host.
> - **Samuel Groß** (saelo) — Google Project Zero researcher; formerly
>   independent / pwn2own; author of two Phrack articles on JavaScript
>   engine exploitation (CVE-2018-4233, CVE-2016-4622). The OffensiveCon
>   2022 "Attacking JavaScript Engines in 2022" talk and the saelo.github.io
>   corpus are the canonical references for what attackers do against the
>   JS engine that Swift apps host through `WKWebView`. Cross-link
>   `mobile_security_expertise.md` and
>   `browser_js_engine_exploitation_expertise.md`.
> - **Trail of Bits iOS / Swift audit team** — security research firm;
>   publications include "Swift Reversing" (Ryan Stortz, 2016) and "Modern
>   iOS Application Security" (Sophia D'Antoine and Dan Guido, 2016).
>   Maintains the Testing Handbook at appsec.guide; ships
>   github.com/trailofbits/semgrep-rules with Swift-specific patterns.
> - **Apple Platform Security team** (institutional) — authors of the Apple
>   Platform Security Guide (Secure Boot, SIP, Code Signing, App Sandbox,
>   Hardened Runtime, ATS); ships CryptoKit with the deliberate `Insecure.*`
>   namespacing; maintains `Security.framework` (Keychain / SecureEnclave /
>   certificate-trust). Cross-link `macos_apple_security.md`.
>
> **Institutional contributors:** Apple Swift team (swift.org blog, swift-
> evolution corpus, migration guides); OWASP MASVS / MASTG (canonical iOS
> audit baseline); NowSecure (App Transport Security and runtime
> instrumentation corpus); Snyk (Swift deserialization security primers);
> Apple Developer Forums and forums.swift.org (the long-running corpus of
> Swift / Obj-C bridging questions and semantic-corner-case discussion).
>
> **What this doc is NOT:** not a Swift tutorial, not a replacement for the
> Apple Platform Security Guide, not a substitute for SwiftLint /
> swift-format / xcodebuild's own warnings, not a reference for iOS
> platform security (in `mobile_security_expertise.md` and
> `macos_apple_security.md`). It is the Swift-specific layer beneath
> cross-language audit heuristics. Read this before reviewing any non-
> trivial Swift codebase; read `code_review_expertise.md` for the click-
> count severity heuristic that lifts each footgun into a triage decision.

Cross-links: `mobile_security_expertise.md` (iOS / Android IPC surface);
`macos_apple_security.md` (Apple platform controls); `code_review_expertise.md`
(click-count severity, candidate-point auditing);
`semgrep_rule_authoring.md` (detection-rule authoring);
`deserialization_expertise.md` (NSKeyedUnarchiver / NSCoding);
`browser_js_engine_exploitation_expertise.md` (JavaScriptCore / WebKit
attack surface hosting every `WKWebView`); `ssrf_url_parsing_expertise.md`
(URL parsing quirks); `cryptography_expertise.md` (CryptoKit `Insecure.*`);
`race_conditions_concurrency_expertise.md` (Sendable / actor isolation);
`c_cpp_footguns_expertise.md` §15 (`Unsafe*Pointer` C-ABI adjacency);
`rust_footguns_expertise.md` §3 (`transmute` analog); `cicd_supply_chain_expertise.md`
§5 (SPM build plugins, `.binaryTarget`).

---

## 1. The behavioral-footgun framing

### 1.1 Safe by default, named unsafe escapes

Swift is marketed as safe: optionals replace null pointers, ARC replaces
manual memory management, array bounds are checked, integer overflow
traps by default, the type system enforces protocol conformance. The
marketing is largely true. *Every footgun in this document* satisfies
a more specific criterion: **the Swift compiler accepts the code without
warning, the default tooling does not flag it (or flags it only with
opt-in SwiftLint rules), the runtime executes it producing the unsafe
behavior**. Swift's unsafe escapes are deliberately *named* —
`Unsafe[Mutable][Buffer]Pointer`, `unsafeBitCast`, `unowned(unsafe)`,
`nonisolated(unsafe)`, `try!`, `as!`, `!`-postfix — and the language
design treats the named-unsafe surface as where the audit should focus.
Production Swift codebases use the named-unsafe surface freely; the
auditor's job is to enumerate every named-unsafe call site and verify
the invariant that justifies it.

A *bug class* answers "what kind of vulnerability is this." A
*behavioral footgun* answers "what does this Swift primitive *do*,
such that ordinary use produces a bug class without the developer
noticing." `try! JSONDecoder().decode(...)` is a primitive whose
default behavior is `fatalError` on any decode failure.
`@IBOutlet weak var label: UILabel!` crashes if the outlet is
dereferenced before the storyboard wires it up.
`WKWebView.evaluateJavaScript("alert('\(userInput)')", ...)` is XSS-
into-WebView.

### 1.2 The Obj-C bridging legacy

Swift is built on the Obj-C runtime on Apple platforms. Every
Foundation type (`NSString`, `NSArray`, `NSDictionary`, `NSData`,
`NSURL`, `NSError`) has a Swift overlay (`String`, `Array`,
`Dictionary`, `Data`, `URL`, `Error`) that bridges at the ABI
boundary. The bridges are correct in the common case and surprising at
the edges: `NSString` is UTF-16-backed, `String` is UTF-8-backed
(since Swift 5.0); bridging silently re-encodes; `String.count`
returns grapheme clusters while `NSString.length` returns UTF-16 code
units. The auditor's job is to know which side of the bridge each
variable lives on.

The Obj-C runtime's *nil-messaging* — silent return of zero / null /
NO on messages to nil — is the other side. Swift removes the footgun
by forcing optional-handling, but the bridge re-introduces it: every
Obj-C-API return is bridged through an Optional, and the developer who
naively force-unwraps reinvents Obj-C nil-messaging in Swift's force-
unwrap clothing.

### 1.3 The ARC reference-counting model

Swift uses Automatic Reference Counting (ARC) for class instances.
Every class reference is *strong* unless declared otherwise (`weak`,
`unowned`); ARC inserts retain/release at every assignment / function-
boundary / scope-exit; the compiler proves balance at compile time.
Deallocation is deterministic — instances drop when the last strong
reference goes. The single load-bearing footgun: **reference cycles**.
Two objects strongly referencing each other never reach refcount zero;
the canonical incarnation is a closure capturing `self` that is also
retained by `self`. The `[weak self]` / `[unowned self]` capture-list
discipline exists exactly to break these cycles.

### 1.4 Audit-cost asymmetry

A developer writes `try!` once. The auditor reads every `try!` call
site and decides whether the called function can throw at runtime.
The Swift compiler does not record "this function is guaranteed never
to throw on this code path" — only the developer's faith does. Each
footgun is a detection target, not just a coding antipattern.

Most Swift footguns are zero-click (crash / leak / data-race without
attacker action). Cross-link `code_review_expertise.md` §"Click-count
severity": an iOS app that crashes is a UX bug; an iOS app that
crashes on a network-attacker-controlled message is denial-of-service;
an iOS app that mishandles a network-controlled message into
`WKWebView.evaluateJavaScript` is RCE at the JS-engine level.

---

## 2. Force-unwrap `!` and implicitly-unwrapped optionals

### 2.1 The `!` postfix on Optional

Swift's `Optional<T>` is an enum with `.some(T)` and `.none`. The `!`
postfix is "force-unwrap": return the wrapped value if `.some`, trap
with `fatalError("Unexpectedly found nil while unwrapping an Optional
value")` if `.none`. The trap is a deliberate language design choice
— Swift made force-unwrap syntactically cheap so developers would use
it only with a proof-by-construction that the optional is non-nil.
The reality: production codebases use `!` freely, often as a
debugging shortcut that ships to production.

```swift
let url = URL(string: someString)!  // crash if not a valid URL
let data = Data(contentsOf: url)!   // crash if remote fetch fails
let json = try! JSONSerialization.jsonObject(with: data)
let dict = json as! [String: Any]   // crash if not a dict
let name = dict["name"]!            // crash if no "name" key
```

Five force-unwraps in three lines. Any one is zero-click DoS. None is
flagged by `swiftc` at default warning level; SwiftLint's
`force_unwrapping` rule is opt-in and classified "idiomatic" rather
than "security". The auditor enumerates every `!` postfix and asks
"what is the proof that this is non-nil?"

### 2.2 Implicitly-unwrapped optionals (IUO)

`T!` is an *implicitly-unwrapped optional*. The compiler treats it as
`T?` in most contexts but auto-unwraps where the surrounding
expression requires `T`. Crash semantics are identical to `!`-postfix.
IUOs exist primarily for Interface Builder outlets:

```swift
class MyViewController: UIViewController {
    @IBOutlet weak var nameField: UITextField!  // nil until storyboard loads
    @IBOutlet weak var submitButton: UIButton!
}
```

IUO is "safe" in this idiomatic use because `viewDidLoad` and later
lifecycle methods run *after* the storyboard wires outlets. The
unsafe variant is the IUO outside the storyboard idiom:

```swift
class APIClient {
    var session: URLSession!  // populated by configure()
    func configure() { session = URLSession(configuration: .default) }
    func get() -> URLSessionDataTask {
        return session.dataTask(with: someURL)  // crash if configure() not called
    }
}
```

The audit pattern: every IUO that isn't `@IBOutlet` needs verification
that no code path reaches the dereference before population.

### 2.3 `as!` force-downcast

`as?` is conditional (returns `T?`); `as!` traps on failure ("Could
not cast value of type X to type Y"). Production codebases use `as!`
pervasively because it eliminates failure-handling at the call site:

```swift
let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
    as! MyCustomCell  // crash if storyboard cell class doesn't match
```

Audit: enumerate every `as!`; verify the cast is provably safe.

### 2.4 `try!` — ignore thrown error

`try!` traps on thrown error ("Fatal error: 'try!' expression
unexpectedly raised an error").

```swift
let data = try! JSONSerialization.data(withJSONObject: dict)
let regex = try! NSRegularExpression(pattern: pattern)
let str = try! String(contentsOf: url)  // any network error → crash
```

`try! String(contentsOf:)` on a URL whose response is attacker-
influenced turns a network glitch into DoS.
`try! NSRegularExpression(pattern: hardcodedPattern)` is *acceptable*
when the pattern is a compile-time constant the developer controls;
`try! NSRegularExpression(pattern: userInput)` is *not*.

### 2.5 The "ship `!` from prototype" anti-pattern

Force-unwrap is a useful prototyping shortcut. The lifecycle reality
is that prototyping `!`s ship to production because nothing in the
toolchain forces removal. The "TODO: replace `!` with proper handling"
comment is the canonical lie.

### 2.6 The "nil → zero" Obj-C bridging surprise

Obj-C messaging to nil returns zero / null / NO silently. Swift's
bridge converts Obj-C nil returns into `Optional.none`. The pattern
`dict.object(forKey:) as! T` is a direct port of Obj-C nil-messaging
that loses the silent behavior and replaces it with a crash. Audit:
look at every Obj-C API call returning nil-on-failure; verify the
nil case is handled rather than force-unwrapped.

---

## 3. `unsafeBitCast`, `withMemoryRebound`, and the `Unsafe*Pointer` family

### 3.1 The `Unsafe*Pointer` types

Swift exposes a named-unsafe pointer family for C-ABI interop and
performance-critical work:

- `UnsafePointer<T>` — typed read-only
- `UnsafeMutablePointer<T>` — typed mutable
- `UnsafeRawPointer` / `UnsafeMutableRawPointer` — untyped
- `UnsafeBufferPointer<T>` / `UnsafeMutableBufferPointer<T>` — typed range
- `UnsafeRawBufferPointer` / `UnsafeMutableRawBufferPointer` — untyped range
- `OpaquePointer` — type-erased C pointer

All eight prefixed `Unsafe`. The naming is deliberate — `grep Unsafe`
finds every call site where the type system is being circumvented.
Semantics follow C: aliasing rules, alignment requirements, strict
typing, no bounds checking, no lifetime tracking. At every call site,
verify (a) pointer is non-nil, (b) buffer has expected size, (c)
bytes have expected type interpretation, (d) pointer does not outlive
buffer. Cross-link `c_cpp_footguns_expertise.md` §15.

### 3.2 `unsafeBitCast(_:to:)` — type punning

`unsafeBitCast` reinterprets bits as a different type. Apple
documentation: "Calling this function breaks the guarantees of the
Swift type system; use with extreme care." Source and destination
must have the same in-memory size and compatible memory layout;
violating either is undefined behavior.

```swift
let bits: UInt64 = 0x4008000000000000
let value = unsafeBitCast(bits, to: Double.self)  // 3.0 — OK
let obj = MyClass()
let raw = unsafeBitCast(obj, to: UInt.self)  // strongly discouraged
```

The second form is *strongly discouraged*: class instances carry
refcount + isa bits, layout is implementation-defined, the bit-
pattern of a reinterpreted class pointer is not stable across Swift
versions. Audit pattern: enumerate every `unsafeBitCast`; verify size
+ layout invariants; deny when destination is class/pointer. Cross-
link `rust_footguns_expertise.md` §3 (`transmute` analog).

### 3.3 `withUnsafeBytes` / `withMemoryRebound` — scope-bound only

The scoped unsafe-access APIs let Swift temporarily reinterpret
memory through an unsafe view. The contract: the closure parameter is
valid *only* for the closure's execution and *must not escape*.

```swift
// CORRECT
data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
    let typedPtr = raw.bindMemory(to: UInt32.self)
    for value in typedPtr { process(value) }
}

// BUG: pointer escapes the closure scope
var storedPtr: UnsafeRawBufferPointer? = nil
data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
    storedPtr = raw  // dangling outside closure
}
let value = storedPtr![0]  // use-after-free
```

The compiler does not catch closure-escape into stored properties.
This is the single largest source of `Unsafe*Pointer` audit findings
in production Swift. Audit: every `withUnsafe*` body — verify the
pointer parameter is not assigned to anything outliving the closure.

### 3.4 Pointer alignment

`Unsafe*Pointer<T>` assumes alignment to `MemoryLayout<T>.alignment`.
The stdlib does not check; misaligned access is UB on most
architectures (traps on ARM, may corrupt on x86).

```swift
data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
    let ptr = raw.baseAddress!.assumingMemoryBound(to: UInt32.self)
    let v = ptr.pointee  // UB if data is not 4-byte aligned
}
```

Use `loadUnaligned(as:)` (Swift 5.7+) or copy bytes into an aligned
location first.

---

## 4. Escaping closures and capture semantics

### 4.1 `@escaping` vs non-escaping

Swift closure parameters are *non-escaping* by default; an `@escaping`
parameter opts into escapability (can be stored, returned, or passed
to other escaping contexts). The compiler enforces structurally — a
non-escaping closure cannot be assigned to a stored property. Every
`@escaping` closure is a candidate for the retain-cycle footgun.

### 4.2 `[weak self]` / `[unowned self]` / strong capture

Closure capture-list controls `self` capture:

| Modifier | Type inside closure | Failure on dealloc |
|---|---|---|
| (default strong) | `Self` | retain cycle |
| `[weak self]` | `Self?` | nil access (handled by Optional) |
| `[unowned self]` | `Self` | **trap** |
| `[unowned(unsafe) self]` | `Self` | **use-after-free** (named-unsafe) |

Audit: every `@escaping` closure capturing `self` — verify capture
list exists and uses `weak` unless `unowned` is provably correct.

### 4.3 The classic retain cycle

```swift
class ViewModel {
    var onUpdate: (() -> Void)?  // stored escaping closure
    func bind() {
        onUpdate = {
            self.refresh()  // strong capture of self → cycle
        }
    }
}
```

Instance leaks forever. Fix: `[weak self] in self?.refresh()` or
`[weak self] in guard let self = self else { return }; self.refresh()`.

### 4.4 `DispatchQueue.async`

GCD-dispatched closures don't form a permanent retain cycle (queue
owns them, not `self`) but extend `self`'s lifetime until the closure
runs. For user-cancelable work, prefer `[weak self]` so the closure
observes deallocation and exits early.

### 4.5 Combine subscription cycles

```swift
class ViewModel {
    var cancellables = Set<AnyCancellable>()
    func bind(publisher: AnyPublisher<Int, Never>) {
        publisher.sink { [weak self] value in
            self?.handle(value)
        }.store(in: &cancellables)
    }
}
```

`[weak self]` here is required: `cancellables` is a stored property
of `self`, so the subscription transitively retains `self`. Without
`[weak self]`, the cycle is established.

---

## 5. ARC and object lifecycle

### 5.1 Strong / weak / unowned

| Modifier | Semantics | Type | Failure |
|---|---|---|---|
| (default) | refcount +1 | `T` | retain cycle |
| `weak` | no refcount; nil-out on dealloc | `T?` | (handled by Optional) |
| `unowned` | no refcount; assumed-alive | `T` | trap on dealloc-then-access |
| `unowned(unsafe)` | unowned w/o runtime check | `T` | use-after-free |

Every `unowned` is a proof-by-construction that the referent outlives
the referrer. The compiler does not check; the auditor does.

### 5.2 `defer` ordering vs `deinit`

`defer` blocks run LIFO at scope exit; `deinit` runs when the last
strong reference drops. ARC deallocation is *deterministic but not
necessarily synchronous* — ARC may insert releases anywhere the
compiler can prove the instance is no longer needed, including before
the textual end of the enclosing scope. Audit: verify `deinit` does
not depend on global mutable state that another thread might mutate.

### 5.3 `final class` vs subclassable

`class Foo` is subclassable; `final class Foo` is not. Subclassable
classes with public state can be subclassed to alter behavior in ways
the original author didn't plan for. Audit: any class participating
in NSSecureCoding, cryptographic protocols, or IPC should be `final`
unless there's a reason it isn't.

### 5.4 `class` vs `struct` (reference vs value)

`class` is reference-typed; `struct` is value-typed. Distinction
matters for Sendable (struct of Sendable members is auto-Sendable;
class needs explicit conformance), COW (applies to struct
collections, not class instances), and mutation. The footgun:
copying a struct does what the developer expects (deep copy);
copying a class reference does not (two aliases to the same
instance). A `var node: GraphNode` (class) passed as a function
argument shares the same instance — concurrent mutation is a race
condition.

### 5.5 `@StateObject` vs `@ObservedObject`

`@StateObject` is *owned* by the view; SwiftUI creates the instance
once per view-identity and reuses across body re-evaluations.
`@ObservedObject` is *injected*; view observes but does not own.

```swift
// BUG: created fresh on every parent re-render
struct MyView: View {
    @ObservedObject var viewModel = ViewModel()
    var body: some View { Text(viewModel.title) }
}
```

This recreates `ViewModel()` every parent re-render, losing all
state. Fix: `@StateObject`. The compiler does not catch the
antipattern. Audit: any `@ObservedObject` with a literal initializer
should be `@StateObject`. Cross-link `macos_apple_security.md`.

---

## 6. Integer overflow and arithmetic

### 6.1 Default trap-on-overflow

Swift's default integer arithmetic *traps* on overflow. `Int.max + 1`
is a guaranteed runtime trap ("Arithmetic overflow"), not UB (as in
C). All signed and unsigned integer types trap on overflow by
default. The opposite of C's default: C's signed-overflow is UB,
unsigned-overflow is wrap. Swift chose to make silent wrap-around an
explicit opt-in.

### 6.2 `&+` / `&-` / `&*` overflow-allowed operators

When the developer *wants* wrap-around (crypto inner loops, hash
functions, bit twiddling):

```swift
let a: UInt32 = 0xFFFFFFFF
let b = a &+ 1   // == 0, no trap
```

The `&` prefix is the ampersand bitwise-AND reused as a "masking
arithmetic" marker. Audit: any `&+` / `&-` / `&*` outside crypto/
hash code is suspicious — opting out of overflow detection where
overflow has security significance (size calc, allocation, indexing).

### 6.3 Integer-type conversion

Converting between integer types: choose the constructor carefully.

- `Int(value)` — traps if doesn't fit
- `Int(truncatingIfNeeded: value)` — truncates bit pattern
- `Int(exactly: value)` — returns `Int?`, nil if doesn't fit
- `numericCast(value)` — uses `init(exactly:)`; traps if doesn't fit

```swift
let big: UInt64 = 0xFFFFFFFFFFFFFFFF
let s1 = Int32(truncatingIfNeeded: big)  // -1 (sign-extended)
let s2 = Int32(big)  // Fatal error: overflow
```

Audit: integer conversion at a trust boundary (file-format parser,
network deserializer, JSON decoder) should use `init(exactly:)` so
failure is recoverable, not a crash.

### 6.4 `String(format:)` format strings

`String(format:)` calls Obj-C's `+[NSString stringWithFormat:]`. The
format-string semantics are C-stdio's `printf`. The footgun is the
classic format-string vulnerability — if the format string is
attacker-controlled, `%@` / `%s` / `%n` directives can leak info
(reading stack / arbitrary memory):

```swift
let userInput = "%@%@%@%@%@%@%@%@%@"  // 9 specifiers, no args
let crash = String(format: userInput)  // reads 9 stack slots as %@
```

Audit: every `String(format:)` call must have the format string as a
compile-time constant; user data passed as arguments only. Cross-
link `code_review_expertise.md` §"Format-string heuristic": format
strings almost always have a better Swift-idiomatic alternative
(string interpolation); a non-literal format string is itself a
finding.

### 6.5 `as` cast between integer types

`as` does NOT convert between unrelated integer types — explicit
constructor is required. This avoids C's silent truncating
`(int)long`. The compiler error is helpful; pick `Int32(exactly:)`
for recoverable failure, `Int32(value)` for trap-on-overflow,
`Int32(truncatingIfNeeded:)` for explicit truncation.

### 6.6 Wrap-when-opting-in discipline

The Swift idiom is "trap by default, opt in with `&`". A hash-
function or PRNG implementation using regular `+` / `-` / `*` on a
hot path is likely (a) buggy — will trap on first overflow — or (b)
incorrect — the algorithm requires modular arithmetic and the
developer used the wrong operator.

---

## 7. String and Unicode surprises

### 7.1 `String` is a Collection of `Character`, not bytes

Swift's `String` is UTF-8-backed (since Swift 5.0); elements are
`Character` values — extended grapheme clusters per Unicode UAX#29.
Iteration yields one human-readable character at a time:

```swift
let str = "👨‍👩‍👧"
print(str.count)                 // 1  — one grapheme cluster
print(str.unicodeScalars.count)  // 5  — Unicode scalars in ZWJ sequence
print(str.utf8.count)            // 18 — UTF-8 bytes
print(str.utf16.count)           // 8  — UTF-16 code units
```

Audit consequence: any "length-of-string" check is ambiguous without
specifying which view. Code comparing `count` against a byte-budget
is wrong. A username field whose "max 32 characters" is enforced via
`count <= 32` allows arbitrary bytes if the user is willing to use
emoji.

### 7.2 `count` is O(n)

`String.count` walks the string to count grapheme clusters — O(n) in
length. Code calling `count` in a tight loop is O(n²). Audit: any
`String.count` inside a loop body is suspicious. Use `String.isEmpty`
(O(1)) when the question is "is there any content".

### 7.3 `String.Index`, not `Int`

Swift strings are not indexed by `Int`. The index type is
`String.Index`. The standard recipe for "character at position 5":

```swift
let str = "hello, world"
let i = str.index(str.startIndex, offsetBy: 5)
let ch = str[i]  // ","
```

Developers porting from `str[5]`-style languages don't compile.
Lorentey's SE-0445 (Swift 6.1) added `CustomDebugStringConvertible`
to `String.Index` so offset arithmetic is debuggable.

### 7.4 NSString bridging surprises

`NSString` is UTF-16-backed; `String` is UTF-8. Bridging re-encodes:

```swift
let s = "café"
let ns = s as NSString
ns.length       // 4  (UTF-16 code units)
s.count         // 4  (grapheme clusters)
s.utf8.count    // 5  (UTF-8 bytes)
s.utf16.count   // 4
```

For ASCII the numbers agree; for non-ASCII they diverge. Developers
who assume `NSString.length` returns character count get surprising
behavior for emoji, combining marks, and non-BMP characters (two
UTF-16 code units each).

### 7.5 `String(cString:)` — UB if not NUL-terminated

`String(cString:)` and `String(validatingUTF8:)` initialize from a
NUL-terminated `UnsafePointer<CChar>`. The initializer walks the
buffer until it finds a NUL byte. If not NUL-terminated, it reads
past the buffer until it either finds a NUL in unrelated memory or
crashes. Audit: every `String(cString:)` needs proof the source
buffer is NUL-terminated. For buffers that aren't, use
`String(decoding:as:)` with an explicit UTF-8 view.

### 7.6 Locale-dependent comparisons

`String` `==` is Unicode-normalization-aware but *not locale-aware*
by default. The "Turkish-I" surprise — `I` and `i` not paired in
Turkish locale — appears with locale-explicit comparisons:

```swift
"TURKEY".caseInsensitiveCompare("turkey")  // .orderedSame
"TURKEY".compare("turkey", options: .caseInsensitive, range: nil,
                 locale: Locale(identifier: "tr"))  // .orderedDescending
```

Audit: case-insensitive comparison on attacker-controlled input must
be locale-explicit, or it has a locale-dependent bypass.

---

## 8. Sendable and concurrency

### 8.1 Swift 6 strict concurrency

Swift 6's strict-concurrency mode (`-swift-version 6` or per-file
`@preconcurrency`) makes data-race detection a compile-time error.
Any value crossing an isolation boundary (actor-to-actor, async-to-
sync, `Task.detached`) must conform to `Sendable`. Swift 6 is now an
aggressive compile-time data-race detector — for codebases that have
opted in. Codebases on Swift 5 with strict concurrency disabled
retain "data races are runtime warnings" behavior. Confirm
`swift-tools-version` in `Package.swift` and `-swift-version` flag in
xcodebuild config; adjust threat model accordingly.

### 8.2 `Sendable` conformance

`Sendable` is a marker protocol requiring data-race-safe storage:

- Value types whose stored properties are all Sendable → auto.
- `final class` with immutable Sendable properties → auto.
- Actors → auto (isolates own state).
- Other classes → not Sendable unless `@unchecked Sendable`.

`@unchecked Sendable` is the "trust me" escape hatch:

```swift
final class Cache: @unchecked Sendable {
    private var storage = [String: Data]()
    private let lock = NSLock()  // discipline invisible to compiler
}
```

Audit: every `@unchecked Sendable` is a developer claim. Verify the
locking discipline explicitly.

### 8.3 Actor isolation and reentrancy

Swift's `actor` provides automatic serialization of access to mutable
state. Calls from outside the actor must be `await`-ed because the
actor may suspend the caller while another caller runs.

Actors are *reentrant*: a suspension point inside an actor-isolated
function allows other actor-isolated functions to interleave. The
single-threaded illusion holds (no two actor methods run at the same
instant), but ordering of suspended-function steps can interleave.
Per SE-0306: "execution of asynchronous actor-isolated functions may
interleave at suspension points."

Audit: any actor-isolated function with multiple `await`s has
implicit interleaving. Invariants holding before the first `await`
may not hold after; invariants holding after the second `await` may
have been mutated by another actor-method between the second and
third `await`. This class — "high-level data race" in Swift Forums
discussion — is the race-condition surface that actor isolation does
not catch.

### 8.4 `@MainActor` and SwiftUI / Combine

`@MainActor` is a global actor isolating code to the main thread.
SwiftUI views and Combine publishers driving UI must run on
`@MainActor`. Moving an isolated type across an isolation boundary
requires Sendable conformance. Compiler enforces in Swift 6; warns
in Swift 5 with strict concurrency; silent without. Audit: any model
touching UI state must be `@MainActor`; any background-thread fetch
returning to update UI must `await MainActor.run { ... }`.

### 8.5 `Task.detached` and lost inheritance

`Task.detached { ... }` creates an unstructured task that does *not*
inherit the parent's actor isolation, task-local values, priority,
or cancellation. Per Apple docs: "Task.detached creates an
independent task not bound to the current scope — you lose automatic
cancellation propagation."

```swift
@MainActor class ViewModel {
    func reload() {
        Task.detached {
            let new = await fetchItems()  // not on MainActor
            await MainActor.run { self.items = new }
        }
    }
}
```

Audit: `Task.detached` is suspicious by default. Prefer structured
(`async let`, `withTaskGroup`) or unstructured-but-inheriting
`Task { ... }`.

### 8.6 `async let` cancellation

`async let` declares a child task whose lifetime is bound to the
enclosing scope. Cancellation propagates into the child; if any
`async let` throws, sibling `async let`s are cancelled. The
semantic is structured-concurrency-correct, but the child task
starts immediately and runs concurrently with the parent. If the
parent doesn't `await` before scope ends, the child is implicitly
awaited at scope exit — order matters for resource cleanup. Cross-
link `race_conditions_concurrency_expertise.md`.

---

## 9. Codable and JSON decoding

### 9.1 `JSONDecoder` strict-by-default

`JSONDecoder().decode(T.self, from: data)`: missing required fields
throw `DecodingError.keyNotFound`; type mismatches throw
`DecodingError.typeMismatch`. Extra fields in the JSON are *silently
ignored*. The latter is a footgun in contexts where polyglot-input
attacks matter; conversely, encoding through a Codable model that's
also used for decoding may drop fields the client expected.

```swift
struct User: Codable {
    let name: String
    let email: String
}
let data = "{\"name\":\"A\",\"email\":\"a@b\",\"admin\":true}".data(using: .utf8)!
let user = try! JSONDecoder().decode(User.self, from: data)
// admin silently dropped; model doesn't know about it
```

Audit: model schemas should match wire schemas with unknown-key
handling explicit.

### 9.2 Custom `init(from:)` — easy to mismatch keys

Manual `Decodable` is required when wire shape differs from Swift
shape. The footgun is mismatched coding keys — JSON has `"user_id"`,
CodingKey case is `.id` returning `"id"`. Fix the raw value:

```swift
enum CodingKeys: String, CodingKey {
    case name
    case id = "user_id"
}
```

Or use `keyDecodingStrategy = .convertFromSnakeCase` (see §9.3).

### 9.3 `keyDecodingStrategy = .convertFromSnakeCase`

Mass-conversion of snake_case JSON keys to camelCase Swift properties.
Pitfalls:

- *Unusual snake-case*: `avatar_url` → `avatarUrl`, but Swift convention
  is `avatarURL` (all-caps initialism); decoder looks for `avatarUrl`.
- *Custom CodingKeys interact*: raw value must be post-conversion, not
  wire form.
- *Leading/trailing underscores*: `_first_name` → `firstName` (leading
  underscore dropped); may be `keyNotFound` instead.
- *Dictionary keys*: `[String: T]` property — dictionary keys are
  *also* converted, rarely what the developer wants.
- *Round-tripping*: encode-then-decode not guaranteed to preserve
  original spelling.

Audit: `keyDecodingStrategy = .convertFromSnakeCase` is correct 80% /
silently wrong 20%. Confirm each model property has the expected wire
correspondence; for any unusual spelling, prefer explicit CodingKeys.

### 9.4 `decode` vs `decodeIfPresent`

`decode(_:forKey:)` throws on missing; `decodeIfPresent(_:forKey:)`
returns nil. Using `decode` for genuinely-optional fields → crashes on
legitimate inputs.

### 9.5 Custom decoders and injected behavior

Codable flexibility includes injecting arbitrary behavior into the
decoding path: `dateDecodingStrategy = .formatted(DateFormatter)`,
`dataDecodingStrategy = .custom { decoder in ... }`,
`userInfo: [CodingUserInfoKey: Any]`. `userInfo` is the only
legitimate way to pass non-decodable state into a decoder; for most
decoders the configuration is developer-controlled and not attacker-
influenced. Audit: decoder configuration must not be attacker-derived.

### 9.6 Date-format defaults

`JSONDecoder().dateDecodingStrategy` defaults to `.deferredToDate` —
`Date(timeIntervalSinceReferenceDate:)`, a Double of seconds since
2001-01-01 UTC. This is *not* what most APIs send (wire convention is
ISO-8601 or Unix epoch). Code failing to set the strategy decodes
dates incorrectly. Audit: every `JSONDecoder()` decoding a model with
`Date` fields needs explicit `dateDecodingStrategy`.

---

## 10. Obj-C bridging and selectors

### 10.1 `@objc` exposes Swift API to Obj-C

`@objc` makes a Swift declaration visible to the Obj-C runtime —
callable via `performSelector`, lookupable via `NSSelectorFromString`,
registerable for KVO. The compiler synthesizes Obj-C-compatible
signatures. Every `@objc` declaration is a candidate for runtime-
string-based invocation. String-based selector lookup that the
attacker can influence becomes a method-call gadget.

### 10.2 `#selector(method)` references

`#selector(MyClass.foo(_:))` produces a typed `ObjectiveCSelector` at
compile time. Under the hood the selector is just a string
(`"foo:"`); a class that adds/removes/replaces methods at runtime can
change what the selector refers to.

### 10.3 `performSelector(_:with:)`

`obj.perform(_: SEL, with: id)` invokes a method by selector,
bypassing static type checking. Arguments are `Any`; return is `Any`.
The runtime resolves the selector to an IMP and jumps.

```swift
let obj = SomeClass()
let sel = NSSelectorFromString("dangerousMethod:")
obj.perform(sel, with: payload)
```

If the selector name is attacker-controlled, this is an arbitrary-
method-call primitive — any `@objc` method on `obj` is reachable.
Cross-link `deserialization_expertise.md`: in Obj-C / Swift,
`performSelector` + `NSKeyedUnarchiver` form the equivalent of Java /
Python deserialization gadget chains.

### 10.4 `responds(to:)`

`obj.responds(to: someSelector)` does runtime capability discovery.
Audit: branch arms after `responds(to:)` should not have wildly
different security properties.

### 10.5 `NSCoder` / `NSKeyedUnarchiver`

NSKeyedArchiver / Unarchiver are the Obj-C-era binary serialization
format. Default `NSCoding` is vulnerable to *object substitution* —
wire format includes class names; the unarchiver instantiates
whatever class the wire specifies. Fix: `NSSecureCoding`, which
requires the receiver to declare expected classes:

```swift
// vulnerable
let obj = NSKeyedUnarchiver.unarchiveObject(with: data)
// NSSecureCoding-aware
let obj = try NSKeyedUnarchiver.unarchivedObject(
    ofClass: MyExpectedClass.self, from: data)
```

Even with NSSecureCoding, `_NSDataFileBackedFuture` is reachable; the
exploit-db CVE-2018-4444 "iMessage NSKeyedUnarchiver Deserialization"
demonstrates this attack. Cross-link
`deserialization_expertise.md` §"Obj-C NSKeyedUnarchiver".

### 10.6 Key-Value Observing (KVO)

KVO uses runtime method swizzling. Observer-registration lifecycle is
*manual* — every `addObserver(_:forKeyPath:options:context:)` needs a
paired `removeObserver` on every code path. Failures:

- Continued KVO callbacks fired at deallocated observer → use-after-
  free crash
- Continued KVO state on deallocated observed object → use-after-free
- Leaked observer that never deregisters → memory leak

SwiftUI / Combine `@Published` is the modern replacement; legacy KVO
code is high-risk.

---

## 11. SwiftUI / UIKit-specific footguns

### 11.1 `@State` resets on parent rebuild

`@State` storage is bound to the view's *identity*. If the parent
rebuilds and assigns a new identity to the child, `@State` resets
silently:

```swift
struct Parent: View {
    @State private var key = UUID()
    var body: some View {
        Child().id(key)  // changing key forces Child to lose @State
    }
}
```

Audit: views with critical state in `@State` should not be parented
by views rebuilding frequently with new identity.

### 11.2 `@Environment` ordering

`.environment` propagates *down* the view tree; lower (closer to leaf)
overrides higher. Code setting environment in wrong order silently
uses wrong value.

### 11.3 Modifier chain ordering

Modifiers compose left-to-right; ordering matters:

- `.background(Color.red).clipShape(Circle())` — red background
  clipped to circle → red circle
- `.clipShape(Circle()).background(Color.red)` — clip first, then
  background *behind* clipped shape → red rectangle behind circle

The compiler doesn't catch the antipattern. Visual review only.

### 11.4 `UIWebView` deprecated (security risk) vs `WKWebView`

`UIWebView` is deprecated since iOS 12, removed iOS 14, was *never*
sandboxed off-process. Any `UIWebView` runs WebKit in the app's own
process — a JS-engine exploit in the page directly compromises the
app. `WKWebView` runs WebKit out-of-process in a sandboxed WebContent
process. Audit baseline: `WKWebView` only. Apple has been rejecting
`UIWebView`-using apps since 2020.

### 11.5 `WKWebView.evaluateJavaScript(_:completionHandler:)`

Runs an arbitrary JS string in the WebView. Footgun: string
interpolation of user data:

```swift
// BUG: XSS into WKWebView
let userMessage = ...  // attacker-controlled
let script = "document.getElementById('msg').innerText = \"\(userMessage)\""
webView.evaluateJavaScript(script)
```

If `userMessage` contains `"; alert('XSS'); //`, the injected JS
runs in the WKWebView content context with access to DOM, cookies,
and any JS bridges installed via `WKScriptMessageHandler`.

Correct pattern: `WKUserScript` for static scripts at document-start
time, or JSON-encode user data before interpolation:

```swift
let encoded = try JSONEncoder().encode(userMessage)
let json = String(data: encoded, encoding: .utf8)!
let script = "document.getElementById('msg').innerText = \(json)"
webView.evaluateJavaScript(script)
```

JSON-encoding is the standard XSS defense for string interpolation
into JavaScript-as-data contexts. Cross-link
`browser_js_engine_exploitation_expertise.md` for the JS-engine
attack surface; saelo Phrack corpus for what attackers do inside.

### 11.6 Deep-link / Universal-Link routing

iOS deep-link surface (custom URL schemes via
`LSApplicationQueriesSchemes`, Universal Links via Associated Domains)
accepts URLs from external contexts. Footgun: *authorization-by-
routing*. An app treating the deep-link path as authorization (e.g.,
`myapp://open-secret/abc123` opens the secret with token abc123)
trusts path contents without verifying originator. Audit: every deep-
link handler must verify the *operation* is authorized for the
*current user*; URL-path arguments are user-influenced input, not a
trust signal. Cross-link `mobile_security_expertise.md`.

---

## 12. File, network, TLS

### 12.1 `URLSession` configuration

`URLSession.shared` and `URLSession(configuration: .default)` ship
with reasonable defaults: TLS verification on, HTTPS-required via ATS
(§12.2), cookies shared. Footgun: custom delegates disabling
verification:

```swift
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // BUG: trust any cert, including attacker MITM
        completionHandler(.useCredential,
                          URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
```

Any production code shipping this pattern is end-to-end insecure.
Audit: every authentication-challenge delegate handler must perform
proper trust evaluation; "accept any cert" paths are findings.

### 12.2 App Transport Security (ATS)

iOS 9+ apps run under ATS by default — outgoing HTTP must be HTTPS
with TLS 1.2+. Exceptions in `Info.plist`:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>  <!-- bypasses ATS entirely -->
    <key>NSExceptionDomains</key>
    <dict>...</dict>
</dict>
```

Apple docs are explicit: exceptions should carve out specific domains,
not bypass ATS globally. Audit: `NSAllowsArbitraryLoads = true` is a
finding. Limited per-domain exceptions are acceptable when justified.
OWASP MASTG-KNOW-0071 has the canonical iOS ATS audit checklist.

### 12.3 `FileManager` symlink-following defaults

`FileManager.copyItem(at:to:)`, `removeItem(at:)`, `moveItem(at:to:)`
follow symbolic links by default. Classic symlink-attack class: if
the source is in an attacker-writable directory, the attacker can
replace the source with a symlink at a sensitive file:

```swift
// BUG: if uploadDir is user-writable, attacker can symlink uploadDir/file
// to /etc/passwd, and the copy reads /etc/passwd
let src = uploadDir.appendingPathComponent("file")
try FileManager.default.copyItem(at: src, to: dst)
```

For paths inside attacker-influenced directories, canonicalize first
(`URL.resolvingSymlinksInPath()`), then verify the canonical path is
within the expected directory. Cross-link `code_review_expertise.md`
§"Absolute path handling" and §"User-input paths must be resolved AND
verified".

### 12.4 `Data(contentsOf:)` for remote URLs — blocking, no timeout

`Data(contentsOf: URL)` is synchronous; for remote URLs (HTTP/HTTPS)
it's a *blocking network call on the calling thread* with no
configurable timeout (default 60s). On main thread → 60s UI freeze;
on a worker → tied-up worker. Audit: any `Data(contentsOf:)` with
`http` or `https` scheme is a finding. Use `URLSession.shared.data(from:)`
(async, configurable timeout).

### 12.5 `URLComponents` parsing surprises

Swift's `URL` / `URLComponents` conform to RFC 3986 (20+ years old)
and do not match how modern browsers process URLs (WHATWG URL spec).
Parsing surprises:

- `URL(string: "http://attacker.com\\@example.com/")` may resolve
  differently in Foundation than browsers
- `URLComponents().path` does not normalize `.` / `..` segments
- `URLComponents().queryItems` percent-decodes values; some encoders
  don't percent-encode reserved chars

Cross-link `ssrf_url_parsing_expertise.md` for the cross-language
URL-parsing surprise corpus. For SSRF-sensitive applications, the
`WebURL` Swift package (Karl Wagner / `karwa/swift-url`) implements
WHATWG URL parsing rather than RFC 3986. Audit: URL parsing where
the URL is attacker-influenced and the parsed result drives an
outbound request needs verification that the parser's interpretation
matches the security-sensitive interpretation.

---

## 13. Cryptographic API

### 13.1 CryptoKit (modern) vs CommonCrypto (legacy)

CryptoKit is Apple's modern crypto API (iOS 13+, macOS 10.15+). Pre-
CryptoKit, CommonCrypto was the C-level library. CryptoKit is type-
safe, has AEAD primitives (AES-GCM, ChaChaPoly), ECDH, ECDSA, EdDSA,
hardware-accelerated where possible. Both APIs are appropriate when
used correctly; audit threshold is correctness, not API choice.

### 13.2 `Insecure.MD5` / `Insecure.SHA1` — namespaced danger

CryptoKit places legacy hash algorithms inside a deliberately-named
`Insecure` enum. API is identical to secure-hash API but namespacing
forces every call site to type "Insecure":

```swift
import CryptoKit
let h1 = SHA256.hash(data: input)             // secure
let h2 = Insecure.MD5.hash(data: input)       // deliberately-named insecure
let h3 = Insecure.SHA1.hash(data: input)
```

Audit: grep `Insecure.` — every occurrence is a finding to verify.
Valid uses limited to interop with legacy systems demanding MD5/SHA1,
cache keys / ETag-style fingerprints (non-adversarial integrity),
git-protocol or historical-compat identifiers. Invalid uses:
password hashing, HMAC, signature verification, cert fingerprinting.
Cross-link `cryptography_expertise.md`.

### 13.3 `SecRandomCopyBytes` and CryptoKit

Canonical Apple-platform CSPRNG is `SecRandomCopyBytes` in
`Security.framework`:

```swift
var bytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard status == errSecSuccess else { fatalError() }
```

CryptoKit provides `SystemRandomNumberGenerator` as the recommended
modern API. Both back onto kernel CSPRNG.

### 13.4 `arc4random()` — historically misnamed but secure

`arc4random()` is BSD libc. Despite the name (RC4 cipher decades ago),
modern macOS / iOS implementations back onto ChaCha20 — appropriate
for crypto use today. Prefer `arc4random_uniform(_:)` over
`arc4random() % N` (no modulo bias).

### 13.5 `Random.random()` is NOT necessarily cryptographic

Swift's `Int.random(in:)`, `Double.random(in:)` use
`SystemRandomNumberGenerator` by default — *is* cryptographically
secure. However, with an explicit custom generator:

```swift
var rng = SeededGenerator(seed: 42)
let r = Int.random(in: 0..<1000, using: &rng)
```

security depends on the generator. Many "seeded generator"
implementations on the web are NOT cryptographically secure (LCG,
Mersenne Twister — predictable from a small number of outputs).
Audit: any `random(in:using:)` with explicit custom generator is
suspicious; the generator must be verified-secure.

### 13.6 The "PoorPRNG with default seed" anti-pattern

```swift
struct SeededRNG: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }
}
var rng = SeededRNG(state: 0)  // seed 0; output deterministic
let token = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
```

Token is fully predictable. Audit: any custom `RandomNumberGenerator`
conformance gets detailed review; LCG-based implementations are
findings.

---

## 14. Swift Package Manager and supply chain

### 14.1 `Package.swift` is executable Swift code

`Package.swift` is not a TOML/YAML declarative manifest — it's a
Swift script compiled and run:

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyPackage",
    products: [.library(name: "MyLib", targets: ["MyLib"])],
    dependencies: [
        .package(url: "https://github.com/foo/bar.git", from: "1.0.0"),
    ],
    targets: [.target(name: "MyLib", dependencies: ["BarLib"])])
```

SPM evaluates this in a sandboxed environment (SE-0303), but the
sandbox is process-level — the script can read filesystem, launch
subprocesses, make network calls (within sandbox ACLs). Build plugins
go further: they produce executable code running as part of the
build. Cross-link `cicd_supply_chain_expertise.md` §5.

### 14.2 The "remote dependency without version-pin" trap

```swift
.package(url: "https://github.com/foo/bar.git", branch: "main")  // BUG: floating
```

Floating a branch picks up any new commit on next `swift package
update`. No checksum verification — package author's GitHub access is
now in your trust boundary. Audit: every `.package(url:...)` should
pin to specific version (`from: "X.Y.Z"`, `exact: "X.Y.Z"`) or commit
(`revision: "abc123..."`); branch / unbounded pins are findings.

### 14.3 Source-control trust model

Pre-Swift 5.7, only package source was Git (typically GitHub).
Swift 5.7+ added Swift Package Registry (SE-0292), but adoption is
slow. Most production codebases still pull from
`github.com/<vendor>/<repo>.git` directly — trust model is "every
dependency implicitly trusting GitHub account integrity for that
repo."

### 14.4 `.binaryTarget` — checksum verification but TOFU

```swift
.binaryTarget(
    name: "SomeFramework",
    url: "https://example.com/SomeFramework.zip",
    checksum: "abc123def456...")
```

Checksum verified at fetch time → prevents mid-transit tampering.
But checksum is trust-on-first-use — no source-provenance, no
signature verification, no reproducible build. If the package author
pushes a malicious binary and updates the checksum, downstream
consumers fetch it on next update. Cross-link
`cicd_supply_chain_expertise.md` §5 (analogous Maven / npm / pip).

### 14.5 Build plugins (SE-0303)

Two flavors: *build tool plugin* (`capability: .buildTool`, generates
code or processes resources at build) and *command plugin*
(`capability: .command`, manually invoked). Both run sandboxed —
filesystem writes limited to per-plugin work directory, but can read
project tree and invoke subprocesses. Audit: every plugin dependency
runs arbitrary plugin code on developer machines at build time;
plugin source must be reviewed alongside the dependency.

---

## 15. Detection patterns

### 15.1 Semgrep patterns

Canonical detection patterns for the org's internal rule-authoring
corpus:

```yaml
# Force unwrap
- pattern: $X!

# try! with I/O
- pattern-either:
    - pattern: try! $F.contentsOf($URL)
    - pattern: try! String(contentsOf: $URL)
    - pattern: try! Data(contentsOf: $URL)

# Force downcast
- pattern: $X as! $T

# Insecure hashes
- pattern-either:
    - pattern: Insecure.MD5.hash(...)
    - pattern: Insecure.SHA1.hash(...)

# UIWebView
- pattern: UIWebView

# WKWebView with non-literal JS
- patterns:
    - pattern: $WV.evaluateJavaScript($JS, ...)
    - pattern-not: $WV.evaluateJavaScript("...", ...)

# URLSession with cert-trust bypass
- pattern: |
    completionHandler(.useCredential, URLCredential(trust: $...))

# Random with custom generator (deny-by-default)
- pattern: $T.random(in: ..., using: &$RNG)

# Legacy NSCoding
- pattern: NSKeyedUnarchiver.unarchiveObject(with: $DATA)
```

XML rule for `NSAllowsArbitraryLoads = true` in Info.plist as a
separate detector. Cross-link `semgrep_rule_authoring.md`.

### 15.2 SwiftLint security-adjacent rules

- `force_unwrapping` (opt-in)
- `force_try` (opt-in)
- `force_cast` (opt-in)
- `implicitly_unwrapped_optional` (opt-in)
- `weak_delegate` (opt-in; retain-cycle delegate patterns)
- `unowned_variable_capture` (opt-in)

Audit: production Swift codebases should enable these with PR-level
justification for any disabled cases. Pre-merge SwiftLint catches a
majority of §2-§5 footguns at PR time.

### 15.3 Trail of Bits Swift Semgrep rules

`trailofbits/semgrep-rules` includes Swift-specific patterns covering
many of the same surfaces; the canonical mirror is the org's
internal rule-authoring workflow corpus.

---

## 16. Defensive checklist and variant analysis

### 16.1 12-item Swift code-review checklist

1. **Force-unwrap audit**: `grep '!'`; ask "what is the non-nil proof"
   at each site.
2. **`try!` / `as!` audit**: enumerate; verify each is justified by a
   compile-time invariant.
3. **IUO audit**: `grep 'var.*: T!'` (excluding `@IBOutlet`); verify
   each has guaranteed-set-before-use lifecycle.
4. **`Unsafe*Pointer` audit**: `grep Unsafe`; verify (size, layout,
   alignment, lifetime) invariants at each call.
5. **`unsafeBitCast` audit**: verify size + layout; deny if
   destination is class or pointer.
6. **`[weak self]` audit**: every `@escaping` closure capturing
   `self` — verify capture list uses `weak` unless `unowned` is
   provably correct.
7. **`Sendable` audit**: in Swift 6 mode, verify every cross-isolation
   send is on a Sendable type. Audit every `@unchecked Sendable` for
   the locking discipline that justifies it.
8. **`Task.detached` audit**: verify the loss of actor context,
   cancellation propagation, and task-local values is intentional.
9. **`Codable` audit**: `JSONDecoder()` has explicit
   `dateDecodingStrategy`, `keyDecodingStrategy`; decoder config not
   attacker-derived.
10. **`NSKeyedUnarchiver` audit**: every `unarchiveObject(with:)`
    should be `unarchivedObject(ofClass:from:)` with explicit allowed
    classes.
11. **`WKWebView.evaluateJavaScript` audit**: JS argument must be
    compile-time literal or JSON-encoded user data; no string
    interpolation.
12. **Crypto-API audit**: grep `Insecure.`, `arc4random`, custom
    `RandomNumberGenerator`; verify each is justified.

### 16.2 Variant analysis: Swift on Server (Vapor / Hummingbird)

Different threat model from iOS:

- **No App Sandbox, no ATS** — TLS configured at application level
  (NIO SSL). Cannot assume Foundation's HTTPS-by-default.
- **No Interface Builder, no IUO outlets** — `@IBOutlet` / `T!`
  antipattern doesn't exist.
- **SQL surface** — Vapor's Fluent ORM uses parameterized queries by
  default; raw `SQLDatabase.raw` bypasses. Cross-link
  `code_review_expertise.md` §"SQL injection".
- **Auth surface** — Vapor `Authenticator` / Hummingbird middleware;
  same threshold as any web framework.
- **HTTP framework surface** — request parsing, header injection, HTTP
  smuggling; same threat model as any HTTP framework.

§1-§13 language-level footguns still apply on the server; platform-
level controls (ATS, sandbox, code signing) do not.

### 16.3 Variant analysis: Embedded Swift

Embedded Swift (SE-0405 through 0407) targets microcontrollers. The
stdlib is subsetted; many runtime features unavailable (no ARC for
some target configurations, no allocator on bare-metal, no
Foundation). Footguns depending on Foundation (Codable, URLSession,
FileManager, Date) don't apply; §1-§6 language-level footguns
(force-unwrap, unsafe-pointer, integer-overflow) all apply with
stronger consequences — typically no crash-handler to catch the
trap on bare-metal. Audit: Embedded Swift needs extra scrutiny on
§1-§6 and *explicit* fault-tolerance discipline at every `!` / `try!`
/ `as!` site, because "crash" = "device hangs".

### 16.4 Variant analysis: SwiftWasm

SwiftWasm compiles Swift to WebAssembly for browser and WASI
targets. Stdlib largely available; Foundation partially-ported.
§1-§13 mostly apply. Output runs in browser's Wasm sandbox; threat
model shifts to "what can the Wasm module read/write through the JS
interop bridge." Cross-link
`browser_js_engine_exploitation_expertise.md`. Cross-link
`code_review_expertise.md` for the broader code-review discipline
lifting each §1-§13 footgun into a triage decision.

---

## 17. References

### Swift language and evolution

- Swift.org documentation: https://www.swift.org/documentation/
- Swift Evolution proposals: https://github.com/swiftlang/swift-evolution
- Swift Language Steering Group: https://www.swift.org/language-steering-group/
- Swift Forums: https://forums.swift.org/
- The Swift Programming Language: https://docs.swift.org/swift-book/

### Key proposals referenced

- SE-0306 Actors: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0306-actors.md
- SE-0303 SPM build tools: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0303-swiftpm-extensible-build-tools.md
- SE-0304 Structured concurrency: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0304-structured-concurrency.md
- SE-0333 withMemoryRebound: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0333-with-memory-rebound.md
- SE-0377 Parameter ownership modifiers: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0377-parameter-ownership-modifiers.md
- SE-0412 Strict concurrency for globals: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0412-strict-concurrency-for-global-variables.md
- SE-0414 Region-based isolation: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0414-region-based-isolation.md
- SE-0445 String.Index printing: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0445-string-index-printing.md

### Apple Developer documentation

- CryptoKit: https://developer.apple.com/documentation/cryptokit
- swift-crypto Insecure namespace: https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Insecure/Insecure_HashFunctions.swift
- UnsafePointer: https://developer.apple.com/documentation/swift/unsafepointer
- withMemoryRebound: https://developer.apple.com/documentation/swift/unsafepointer/withmemoryrebound(to:capacity:_:)
- unsafeBitCast: https://developer.apple.com/documentation/swift/unsafebitcast(_:to:)
- WKWebView.evaluateJavaScript: https://developer.apple.com/documentation/webkit/wkwebview/evaluatejavascript(_:completionhandler:)
- URLComponents: https://developer.apple.com/documentation/foundation/nsurlcomponents
- ATS configuration: https://developer.apple.com/news/?id=jxky8h89
- Apple Platform Security: https://support.apple.com/guide/security/welcome/web

### Concurrency

- Adopting strict concurrency in Swift 6: https://developer.apple.com/documentation/swift/adoptingswift6
- Embracing Swift concurrency (WWDC25): https://developer.apple.com/videos/play/wwdc2025/268/
- Beyond the basics of structured concurrency (WWDC23): https://developer.apple.com/videos/play/wwdc2023/10170/
- Swift 5.10 Released: https://www.swift.org/blog/swift-5.10-released/
- Swift 6.1 Released: https://www.swift.org/blog/swift-6.1-released/

### Researcher homepages

- Chris Lattner: https://nondot.org/~sabre/
- John McCall: https://rjmccall.github.io/
- Doug Gregor: https://www.douggregor.net/
- Joe Groff: https://github.com/jckarter
- Karoy Lorentey: https://github.com/lorentey
- Filip Pizlo: https://www.filpizlo.com/ and https://webkit.org/blog/author/fpizlo/
- Samuel Groß (saelo): https://saelo.github.io/

### iOS / Swift audit corpora

- OWASP MASVS / MASTG: https://mas.owasp.org/
- OWASP MASTG-KNOW-0071 (iOS ATS): https://mas.owasp.org/MASTG/knowledge/ios/MASVS-NETWORK/MASTG-KNOW-0071/
- Trail of Bits publications: https://github.com/trailofbits/publications
- Trail of Bits Testing Handbook: https://appsec.guide/
- Trail of Bits Semgrep rules: https://github.com/trailofbits/semgrep-rules
- HackTricks iOS WebViews: https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting/ios-webviews
- HackTricks iOS Serialisation: https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting/ios-serialisation-and-encoding
- NowSecure ATS guide: https://www.nowsecure.com/blog/2017/08/31/security-analysts-guide-nsapptransportsecurity-nsallowsarbitraryloads-app-transport-security-ats-exceptions/
- Snyk Swift deserialization primer: https://snyk.io/blog/swift-deserialization-security-primer/

### JavaScriptCore / WebKit (the WKWebView surface)

- Project Zero JSC exploits index: https://googleprojectzero.blogspot.com/2019/08/jsc-exploits.html
- Project Zero JITSploitation: https://projectzero.google/2020/09/jitsploitation-one.html
- Project Zero iOS Safari sandbox escape: https://projectzero.google/2023/10/an-analysis-of-an-in-the-wild-ios-safari-sandbox-escape.html
- Saelo OffensiveCon 2022: https://saelo.github.io/presentations/offensivecon_22_attacking_javascript_engines.pdf
- Saelo "3 Years of Attacking JS Engines": https://gist.github.com/saelo/dd598a91a27ddd7cb9e410dc92bf37a1

### Static analysis

- SwiftLint rule directory: https://realm.github.io/SwiftLint/rule-directory.html
- SwiftLint force_unwrapping: https://realm.github.io/SwiftLint/force_unwrapping.html

### Tooling

- swift-url (WHATWG URL): https://github.com/karwa/swift-url
- swift-crypto: https://github.com/apple/swift-crypto
- swift-package-manager: https://github.com/swiftlang/swift-package-manager
- Swift Collections: https://github.com/apple/swift-collections
- Vapor: https://github.com/vapor/vapor
- Hummingbird: https://github.com/hummingbird-project/hummingbird

### Cross-references within this expertise corpus

- `mobile_security_expertise.md` — iOS / Android runtime, IPC, deep links
- `macos_apple_security.md` — Apple platform security (SIP, TCC,
  App Sandbox, Hardened Runtime, code signing, notarization)
- `code_review_expertise.md` — click-count severity, candidate-point
  auditing, format-string / path / serialization heuristics
- `semgrep_rule_authoring.md` — Semgrep rule authoring discipline
- `deserialization_expertise.md` — NSKeyedUnarchiver as Swift / Obj-C
  incarnation of cross-language deserialization bug class
- `browser_js_engine_exploitation_expertise.md` — JavaScriptCore /
  WebKit attack surface hosting Swift `WKWebView`
- `ssrf_url_parsing_expertise.md` — URL-parsing quirks in `URL` /
  `URLComponents` / `URLSession`
- `cryptography_expertise.md` — CryptoKit `Insecure.*` namespace
- `race_conditions_concurrency_expertise.md` — Sendable / actor
  isolation as cross-language concurrency surface
- `c_cpp_footguns_expertise.md` §15 — `Unsafe*Pointer` adjacency
  where Swift meets the C ABI
- `rust_footguns_expertise.md` §3 — `transmute` analog of
  `unsafeBitCast`
- `cicd_supply_chain_expertise.md` §5 — SPM build plugins,
  `.binaryTarget` checksum surface
