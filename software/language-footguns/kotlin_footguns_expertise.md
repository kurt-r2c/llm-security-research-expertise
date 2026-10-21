# Kotlin Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Andrey Breslav, Roman Elizarov, Hadi Hariri, Jake Wharton, Christina Lee, Manuel Vivo, Vladimir Reshetnikov, and the institutional Android / OWASP MASVS / GitHub Security Lab Android research corpus

> **Currency marker:** Last refreshed 2026-05-14. This expertise doc continues the
> **language-specific behavioral footgun** class — primitives whose unsafe behavior is
> the *default*, separate from cross-language bug-class taxonomy. Kotlin is unusual in
> the catalog: it was explicitly designed in 2010-2016 as an "improved Java," so much
> of its surface is *safer* than the Java baseline (null safety, immutability defaults,
> exhaustive `when`, no checked exceptions). But Kotlin compiles to JVM bytecode and
> inherits the Java standard library wholesale, which means most Java footguns
> (`ObjectInputStream`, JNDI lookup, `XMLInputFactory` default DTD processing,
> `Cipher.getInstance("AES")` ECB default, `Class.forName(USER)`) reach into Kotlin
> verbatim. Kotlin also *adds* its own footgun class: `lateinit`, `!!`, platform types
> from Java interop, `GlobalScope.launch`, `runBlocking` inside coroutine context,
> scope-function receiver confusion, type-erasure-without-`reified`. The post-1.6
> coroutines model elevated structured concurrency to the dominant Android +
> Kotlin-server pattern, with its own discipline failures (cancellation swallowing,
> `Thread.sleep` inside `suspend`, `Dispatchers` confusion). Recent additions: K2
> compiler GA (Kotlin 2.0, May 2024) shipping a rewritten frontend; Compose Multiplatform stable for desktop and iOS; Kotlin 2.4 context
> parameters (stable replacement for context receivers); Spring Boot 3.4 Kotlin JPA
> regression with `@Version` annotation; ongoing CVE stream in Android Parcel
> deserialization (CVE-2023-20963, CVE-2022-20452, EvilParcel CVE-2017-13315) where
> Kotlin Parcelable codegen reads the same wire format as Java.
>
> **Researchers:**
>
> - **Andrey Breslav** — Kotlin lead designer at JetBrains 2010-2020; oversaw
>   Kotlin 1.0-1.4 design, wrote large portions of the compiler, served on the
>   JCP Expert Group for JSR 335 (Project Lambda), President of the Kotlin
>   Foundation 2018-2020, co-founded JSpecify for JetBrains. The decisions to
>   make every type nullable-or-not at the type level and to treat Java types as
>   *platform types* with `!` suffix are direct outputs of his leadership.
>   `abreslav.com/bio`, `blog.jetbrains.com/author/andrey-breslav/`.
> - **Roman Elizarov** — Kotlin Project Lead at JetBrains since November 2020;
>   designer of Kotlin coroutines and the kotlinx.coroutines library since 2016;
>   pre-JetBrains career at Devexperts on high-performance JVM trading software.
>   "GlobalScope is delicate API" + structured-concurrency rationale are his
>   published positions. `elizarov.medium.com`,
>   `blog.jetbrains.com/kotlin/2020/11/roman-elizarov-is-the-new-project-lead-for-kotlin/`.
> - **Hadi Hariri** — VP of Program Management at JetBrains, previously VP of
>   Developer Advocacy; host of *Talking Kotlin* podcast; long-running advocate-side voice
>   framing Kotlin as "Java's problems, solved." Author of Spek and Wasabi.
>   `blog.jetbrains.com/team/2019/09/02/help-and-inspire-interview-with-hadi-hariri-...`,
>   `talkingkotlin.com`.
> - **Jake Wharton** — Android engineer at Cash App / Square / Google. Kotlin/
>   Android library author (Retrofit, Picasso, Otto, ButterKnife, Molecule,
>   Mosaic). At Google 2017-2020: Kotlin style guide, KTX libraries, framework
>   nullability annotations, R8, view binding. Canonical practitioner
>   voice on Kotlin idioms in production. `jakewharton.com`,
>   `github.com/JakeWharton`.
> - **Christina Lee** — Android engineer on the Core UI team at Pinterest;
>   KotlinConf and Google I/O speaker on Kotlin null-safety and FRP. Published positions on null-safety-as-adoption-
>   driver. `talkingkotlin.com/kotlin-at-pinterest-with-christina-lee/`,
>   `github.com/christinalee`.
> - **Manuel Vivo** — Staff Android Engineer at Bumble; previously Android DevRel
>   engineer at Google; authored canonical Android coroutines guidance
>   (`viewModelScope`, `lifecycleScope`, `repeatOnLifecycle`, Flow patterns,
>   `Dispatchers.IO` discipline) on developers.android.com and the Android
>   Developers Medium publication. `manuelvivo.dev`,
>   `github.com/manuelvicnt`.
> - **Vladimir Reshetnikov** — Acknowledged in the official Kotlin language
>   specification (authored by Marat Akhin and Mikhail Belyaev) for help and
>   feedback. `kotlinlang.org/spec/kotlin-spec.html`,
>   `github.com/VladimirReshetnikov`.
> - **Trail of Bits Android / Kotlin audit corpus** — institutional. The
>   Testing Handbook (`appsec.guide`) and Claude Code skills plugins
>   (`github.com/trailofbits/skills`) include `firebase-apk-scanner` and
>   `audit-context-building`. Android security research runs through
>   `blog.trailofbits.com/categories/audits`.
> - **OWASP MASVS / MASTG authors** — institutional. MASVS and MASTG at
>   `mas.owasp.org` are the canonical baseline: MASVS-STORAGE, CRYPTO, AUTH,
>   NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY. MASVS refactor 2023 moved
>   verification levels (L1, L2, R) into MASTG as Testing Profiles.
> - **GitHub Security Lab Android team** — institutional. Android-
>   deserialization research thread at
>   `securitylab.github.com/resources/android-deserialization-vulnerabilities/`
>   catalogues the Parcel/Bundle bug class hitting Kotlin Parcelable codegen
>   the same way it hits Java. Bednarski's `LeakValue` for CVE-2022-20452 is
>   the canonical post-2020 disclosure. `github.com/michalbednarski/LeakValue`.
>
> **Cross-links to neighboring expertise docs:**
> - `java_footguns_expertise.md` — the Java parent of Kotlin's JVM inheritance.
>   Every JVM-layer footgun in that doc (`ObjectInputStream`, JNDI, JNDI/LDAP/RMI
>   lookup, default `XMLInputFactory` DTD processing, `Cipher.getInstance` ECB
>   default, `Class.forName(USER)`, `Runtime.exec(String)` argv parsing, Spring
>   SpEL/OGNL eval primitives, JAR-supply-chain surface) is also a Kotlin
>   footgun by inheritance. This doc covers what Kotlin *adds*; the Java doc
>   covers what Kotlin *inherits*.
> - `mobile_security_expertise.md` — Android-specific surface that this doc
>   touches in §11 (Activity lifecycle, intent attacks, Parcelable, Room, deep
>   links, `WebView.addJavascriptInterface`); the full Android catalog lives
>   there.
> - `code_review_expertise.md` — manual-audit methodology that applies on top of
>   these primitives. Audit recipe: enumerate every `!!`, every `lateinit`,
>   every `GlobalScope.launch`, every `as` (unchecked) cast, every `@JvmStatic`
>   companion-object boundary, every Java-interop entry point.
> - [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) — rule design for detecting these patterns at
>   scale, including the Kotlin-specific Semgrep grammar.
> - `race_conditions_concurrency_expertise.md` — happens-before, JMM, and the
>   coroutines-on-JVM concurrency surface (carrier thread pinning,
>   `Dispatchers.IO` exhaustion, mutex contention, atomic primitives).
> - `cicd_supply_chain_expertise.md` — Gradle Kotlin DSL config-time execution
>   surface; Maven Central / GitHub Packages dual-registry trust model; KSP
>   plugin trust.
> - `cryptography_expertise.md` — JCA / `javax.crypto` defaults that Kotlin
>   inherits from Java (ECB-by-default AES, IV reuse, PBKDF2 iteration counts).
> - `deserialization_expertise.md` — cross-language deserialization
>   gadget-research thread; the Kotlin codegen path through Jackson, kotlinx-
>   serialization, and Parcelable is a Kotlin-specific entry into the
>   deserialization sink surface.

---

## 1. The Behavioral-Footgun Framing

### Why "footgun" is the right primitive of analysis

A *cross-language bug class* (SQL injection, deserialization, SSRF, command
injection) is defined by attacker control over a particular semantic operation. A
*behavioral footgun* is the inverse: a language-internal primitive whose default
behavior is unsafe regardless of attacker control. The two views overlap but are
not equivalent. Reading `lateinit var x: T` before initialization is a
*Kotlin-specific* behavioral footgun whose runtime is
`UninitializedPropertyAccessException` — a denial-of-service primitive an attacker
can trigger by manipulating object construction order via DI configuration, test
harness setup, or any path that bypasses the framework-mandated init.

The footgun lens forces the question: **what does the language guarantee by
default, and what does it require the developer to opt into?** When a language
defaults to *safe* behavior, the developer must opt *in* to the unsafe primitive,
which produces a visible review point. When the language defaults to *unsafe*, the
burden of "did the developer remember to opt out" is permanent. Kotlin is
*partially* in the safe-by-default camp (null safety, immutability, structured
concurrency), which is why it earned its post-2017 Android-default position. But
Kotlin compiles to JVM bytecode, and the JVM is unambiguously unsafe-by-default.
The Kotlin footgun catalog has two distinct origins.

### Kotlin's "improved Java" framing and the JVM inheritance

The Kotlin design rationale (Breslav's 2010-2020 era) is explicit: take what works
in Java, remove what doesn't, add what should have been there. Kept: the JVM, JCA,
the Java standard library, JIT performance, the Maven Central ecosystem. Removed:
null pointers as a runtime concept, verbose getter/setter boilerplate, checked
exceptions, equality-as-reference, mutable-by-default. Added: properties as
first-class members, `when` expressions, data classes, extension functions, smart
casts, coroutines as a language primitive, scope functions in the standard
library.

The result is a language whose *surface* is safer than Java in several ways
(nullability-at-the-type-level is the dominant one) and whose *bytecode* is
identical to Java's. `Class.forName("attacker.controlled.class")`,
`Cipher.getInstance("AES")` defaulting to ECB, `ObjectInputStream.readObject()`
accepting classpath gadgets, JNDI lookup — all hit the same code paths in Kotlin
as in Java. The deserialization advisories listed in `java_footguns_expertise.md`
§2-§5 all apply to Kotlin services. **The Kotlin-language surface adds null
safety, structured concurrency, immutability defaults, and exhaustive `when`; the
Kotlin-bytecode surface preserves every Java JVM footgun.**

### The "two layers of risk" frame

A Kotlin audit has two layers:

1. **Kotlin-language primitives** — `lateinit`, `!!`, `as T` unchecked casts,
   platform types `T!` from Java interop, scope-function receiver confusion,
   `GlobalScope.launch`, `runBlocking` in coroutine context, swallowed
   `CancellationException`, mutable `data class` fields as map keys, type erasure
   without `reified`. Detection is mechanical pattern-matching on Kotlin syntax.
2. **JVM-inherited primitives** — every pattern in
   `java_footguns_expertise.md` from §2 (Java Serialization) through §13
   (cryptographic defaults). Detection requires reading both Kotlin call sites
   *and* the Java APIs they invoke.

This doc focuses on layer 1 in §2-§12 and reaches into layer 2 in §13-§14.

### Scope

Covers Kotlin-language primitives whose default behavior is unsafe in
production threat models (server-side untrusted-data, Android, Compose desktop,
multiplatform). Does not duplicate cross-language bug-class coverage
(`deserialization_expertise.md`, `shell_injection_expertise.md`), protocol-layer
issues, rule-authoring methodology (the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview)), or general
Android attack surface (`mobile_security_expertise.md` §7). Selection criterion:
*if you handed this primitive to a developer with no prior Kotlin security
context, what is the probability they would deploy it unsafely?* Anything above
~40% qualified.

---

## 2. `lateinit` and Uninitialized State

### The primitive

`lateinit var x: T` promises initialization after declaration but before first
read. The compiler skips its usual not-null-at-construction guarantee; reading
before init throws `kotlin.UninitializedPropertyAccessException` ("lateinit
property x has not been initialized"). This is a runtime exception, not a
compile-time error.

```kotlin
class UserRepository {
    lateinit var apiClient: ApiClient
    fun load(id: String) = apiClient.fetch(id)  // throws if init didn't run
}
```

Intended use: DI frameworks set the property after construction; the contract is
"trust me; the framework initializes before any application call." The failure
mode is what happens when the framework does not.

### Failure modes

1. **DI misorder.** A Dagger/Hilt scope mismatch, a Spring profile that omits a
   bean, a Spring Boot `@ConfigurationProperties` constructor binding that
   doesn't satisfy the contract (issue 35603 in spring-projects/spring-boot
   tracks exactly this) — the first call site throws.
2. **Pre-init leak.** Constructor-time callbacks, `init { }` blocks, or super-
   class init can reach the `lateinit` before the DI framework's post-
   construction phase has run.
3. **Test-only init leak.** A test fixture primes the property; the prod path
   doesn't. Tests ship green; prod fails on first request.
4. **Mock leak.** `@MockK lateinit var` reused across test classes; annotation
   order is implementation-specific. Surfaces as flaky tests.

### Restrictions and the safer alternative

`lateinit` cannot be used for primitive types (`Int`, `Boolean`, `Long`) or
nullable types. Primitives have a guaranteed-zero default so "uninitialized" is
not distinguishable from "initialized to zero"; nullable types already express
the "not yet present" state.

The safer alternative is `by lazy { }`:

```kotlin
val apiClient: ApiClient by lazy { ApiClientFactory.create() }
```

`by lazy` initializes on first read; the block runs exactly once and is
thread-safe by default (`LazyThreadSafetyMode.SYNCHRONIZED`). The trade-off: the
initializer must be self-contained, forcing the developer to confront "where
does the dependency come from" at declaration time rather than deferring to the
framework.

### The `::property.isInitialized` discipline

Kotlin 1.2+ allows checking whether a `lateinit` is initialized:

```kotlin
fun safeLoad(id: String): Result<User> =
    if (::apiClient.isInitialized) Result.success(apiClient.fetch(id))
    else Result.failure(IllegalStateException("apiClient not initialized"))
```

Converts a runtime throw into a controlled branch. Load-bearing in code paths
where the framework-init contract is uncertain.

### Audit recipe

1. Find the *unique* init site per `lateinit`. Multiple init sites = document
   which runs in prod.
2. Trace constructor → first read. If any code between construction and the
   framework's post-construction callback can reach the property, switch to
   `by lazy` or constructor injection.
3. Flag any `lateinit` whose init lives only in a test fixture.
4. Require `::property.isInitialized` guards where init runs under a profile-
   conditional `@Configuration`.

Sources: `baeldung.com/kotlin/checking-lateinit`, `okkotlin.com/lateinits/`.

---

## 3. `!!` Null Assertion + Nullable-Type Bypass

### The primitive

Kotlin's type system distinguishes nullable (`T?`) from non-nullable (`T`) at
the type level. `!!` converts a nullable value to non-nullable by *asserting*
(at runtime, with no static guarantee) that the value is non-null. If the
assertion fails, the runtime throws `NullPointerException` (or
`KotlinNullPointerException` in older versions) with only the line number — no
information about which `!!` in a chain fired.

```kotlin
val name: String = user.profile?.displayName!!  // throws if profile or displayName is null
```

Intended use: the rare moment when the developer has more information than the
compiler — typically Java interop or post-validated JSON parsing. In practice
`!!` is widely overused as a quick fix for "the compiler complains and I don't
want to think about it." Every `!!` is a future bug report.

### The risks

1. **NPE with no debugging info.** `a!!.b!!.c!!.d` gives one line number for
   four assertion points.
2. **Strips nullability contract from the type system.** Downstream code treats
   the value as non-null; later refactors that re-introduce a nullable path
   silently break the contract — no compiler warning.
3. **Test/prod skew.** Tests use non-null fixtures; prod hits an attacker-
   influenced null. `!!` becomes a remote DoS primitive.
4. **Chained `!!` compounds probability.** Four `!!`s at 99% non-null each give
   a 96% compound — a 4% hot-path crash rate is unshippable.

### Safer alternatives

| Primitive | Behavior | When to use |
|---|---|---|
| `value?.method()` | Safe-call: returns `null` if `value` is null | Default for nullable chains |
| `value ?: default` | Elvis: substitute default | When a sensible default exists |
| `value?.let { ... }` | Block runs only if non-null | When the non-null branch is multi-statement |
| `requireNotNull(value) { "msg" }` | Throws `IllegalArgumentException` with custom message | Function-parameter precondition |
| `checkNotNull(value) { "msg" }` | Throws `IllegalStateException` with custom message | Invariant assertion on internal state |
| `value as? T` | Safe-cast: returns `null` on mismatch | When the cast might fail |
| `value!!` | Throws `NullPointerException` on null | Rarely; document why |

`requireNotNull` / `checkNotNull` preserve the runtime crash but upgrade the
exception class and add a custom message — significant diagnostic improvement
in bug reports. Sources: `kotlinlang.org/docs/null-safety.html`,
`baeldung.com/kotlin/not-null-assertion`,
`discuss.kotlinlang.org/t/not-null-assertion-is-pointless/30154`.

### Detection

`detekt`'s `UnsafeCallOnNullableType` flags `!!`. Detekt issue 4832 tracks
disallowing `!!` entirely. Pragmatic baseline: no new `!!` in code review
without a comment explaining why; legacy `!!` documented and gradually
replaced.

### Audit recipe

1. Document reasoning per `!!`: why not `?.let` / `?:` / `requireNotNull`.
2. For "never null because business logic validates upstream," prefer
   `checkNotNull(x) { "business-rule X expected non-null Y" }` to preserve
   intent in the exception.
3. Treat chained `!!` (`a!!.b!!.c!!`) as a code smell; rewrite as `let` chain.
4. For platform-type sources (§4), `!!` is almost always wrong — eliminate at
   the Java-interop boundary.

---

## 4. Platform Types and Java Interop

### The primitive

When Kotlin code references a Java type, the Kotlin compiler does not know
whether that type is nullable in Java (Java's type system has no such
concept). The compiler represents the type as a **platform type**, denoted `T!`
in error messages (not in source code — `!` is not a spellable type operator).
A platform type is treated as both nullable and non-nullable simultaneously:
the compiler allows operations that would require either. The developer can
assign to either `T` or `T?`; assigning to `T` inserts a runtime null check.

```kotlin
// Java: public class UserDao { public String findEmail(long id) { return null; } }
val email = dao.findEmail(42L)     // inferred: String! (platform)
val nonNullEmail: String = email   // OK; runtime check inserted
val nullableEmail: String? = email // OK; explicit nullable
println(email.length)              // NPE at runtime if email is null
```

The footgun is that **platform types break Kotlin's null-safety guarantee** at
every Java-interop boundary. A Kotlin caller of an un-annotated Java API has
no compile-time warning; the call site looks identical to a Kotlin-only
non-nullable call site. This is the most common Kotlin NPE class.

### Annotations that help

Kotlin recognizes nullability annotations from JetBrains, JSpecify, JSR-305,
Eclipse, Android Support, Findbugs, and the Checker Framework. When
present, Kotlin treats the type as the corresponding nullable or non-nullable
type — no platform type at all. Spring Framework, Jakarta EE, Guava, JDK 9+
collections, AndroidX ship with annotations; older or internal Java code
often does not.

JSpecify (`jspecify.dev`, co-founded by Breslav for JetBrains 2018-2020) is the
cross-vendor effort to standardize Java nullability annotations. Until adoption
is universal, platform types remain the dominant interop nullability mechanism.

### The "propagating platform types" anti-pattern

Effective Kotlin Item 3 (Moskała, `kt.academy/article/ek-platform-types`)
names the anti-pattern: a function that takes a platform-typed parameter and
returns a platform-typed result. The "infection" spreads through the codebase.
Discipline: **eliminate platform types at the call site** — assign to `T` or
`T?` explicitly.

```kotlin
// Anti-pattern: platform type spreads
fun loadAndProcess(id: Long): String {
    val email = dao.findEmail(id)  // String! (platform)
    return email.lowercase()       // NPE here if null
}

// Recommended: eliminate at boundary
fun loadAndProcess(id: Long): String? {
    val email: String? = dao.findEmail(id)
    return email?.lowercase()
}
```

### Audit recipe

1. Identify every Java-interop boundary; check whether each Java API has
   nullability annotations.
2. For unannotated APIs, wrap calls in a Kotlin adapter returning explicit
   `T?` or `T`.
3. Eliminate platform types at the call site.
4. For internal Java code, add JSpecify annotations incrementally.

Sources: `kotlinlang.org/docs/java-interop.html`,
`kotlinlang.org/docs/java-to-kotlin-nullability-guide.html`,
`baeldung.com/kotlin/platform-types`.

### Companion JVM interop annotations

The reverse direction (Java's view of Kotlin code) also has footguns:

- **`@JvmStatic`** — Promotes a companion-object member to a true Java static.
  Without it, Java sees `Companion.foo()` (two-level access). Does not work on
  `val` properties as a field — `val` compiles to a method.
- **`@JvmField`** — Exposes a Kotlin property as a true Java field, bypassing
  getters/setters and any Kotlin-side validation. Cannot combine with
  `@JvmStatic`.
- **`@JvmOverloads`** — Generates N overload methods (one per defaultable
  position) for Java callers. Changing a default parameter's nullability
  silently changes the generated Java overload signatures — source-
  incompatible API change for Java consumers.
- **`@JvmName`** — Renames the JVM method. Kotlin and Java identifiers differ
  silently; footgun for documentation and bytecode debugging.

Adding/removing `@JvmField` or `@JvmOverloads` is an API break.

---

## 5. Companion Objects and Static-Like State

`companion object` is Kotlin's static-state analog — a singleton attached to
a class declaration. `object Foo` is the same singleton primitive without an
enclosing class.

```kotlin
class HttpClient(private val baseUrl: String) {
    companion object {
        const val DEFAULT_TIMEOUT_MS = 30_000L
        fun forSemgrep(): HttpClient = HttpClient("https://semgrep.dev/api/")
    }
}
```

Footguns:

1. **Companion-object init order.** Companion objects initialize when the
   enclosing class loads; cross-class order is class-loader-dependent. A
   companion init that depends on another can race or hit
   `ExceptionInInitializerError`.
2. **`init { }` block ordering.** Blocks run in source-textual order; mixing
   property initializers with `init` blocks produces surprises.
3. **Mutable companion state is process-global.** Any `var` is shared without
   synchronization (cross-link `race_conditions_concurrency_expertise.md`).
4. **`@JvmStatic` is one-way additive.** Adding `@JvmStatic` promotes
   `MyClass.Companion.method()` to `MyClass.method()` for Java callers;
   removing it breaks Java consumers.

Audit recipe: confirm no `var` mutable fields (or document synchronization);
treat companion-object state as process-global JMM-shared state.

---

## 6. Scope Functions (`let`, `run`, `apply`, `also`, `with`)

### The primitive

Kotlin's standard library ships five scope functions that execute a lambda in
the context of a receiver. They differ in two axes: how the lambda references
the receiver (`this` vs `it`) and what the function returns (the receiver vs
the lambda's last expression).

| Function | Receiver in lambda | Return value | Common use |
|---|---|---|---|
| `T.let { it -> ... }` | `it` | lambda result | Null-safe chain on `T?` |
| `T.run { this -> ... }` | `this` | lambda result | Multi-statement transform on `T` |
| `with(T) { this -> ... }` | `this` | lambda result | Block on existing receiver |
| `T.apply { this -> ... }` | `this` | receiver `T` | Builder-style configuration |
| `T.also { it -> ... }` | `it` | receiver `T` | Side-effect in a chain |

### The "I meant `also` but wrote `apply`" failure mode

Most common scope-function bug: swapping `apply` ↔ `also` (both return
receiver, differ on `this` vs `it`) or `let` ↔ `run` (both return lambda
result, differ on `it` vs `this`). The compiler does not catch the swap;
the bug manifests as the wrong value being returned from a chain, or the
wrong object being modified.

```kotlin
val builder = Request.Builder()
    .url(api)
    .apply { addHeader("Authorization", token) }  // returns builder
    .build()
```

Swap to `.let { it.addHeader(...) }` and the chain's return type silently
becomes whatever `addHeader` returns. Benign if that's also `Builder`; broken
if the types diverge.

### `run` is both a scope function AND a top-level function

Top-level `run { }` (no receiver) runs a block and returns its result.
`T.run { }` is an extension. In a chain, `expr.run { }` is the extension;
standalone `run { }` is top-level. Refactoring a chained `run` into a
statement changes semantics.

### Nesting hazards

```kotlin
foo.apply {
    bar.let { it.process() }   // inside apply: this=foo; inside let: it=bar
    process()                  // ambiguous: foo.process() or bar.process()?
}
```

The naked `process()` resolves to `foo.process()`. Reader can easily
misattribute the receiver; compile-time is correct, human review is not.

### Audit recipe

1. Flag nested scope functions; require `this@FunctionName` or `it`
   disambiguation.
2. For every `apply` in a chain, confirm the lambda's last expression is not
   the intended return value.
3. For every `let` in a chain, confirm the developer intended the lambda
   result, not the receiver.

Sources: `kotlinlang.org/docs/scope-functions.html`,
`baeldung.com/kotlin/scope-functions`.

---

## 7. Coroutines and Structured Concurrency

### The primitive

Kotlin coroutines (kotlinx.coroutines) introduce *suspending functions* as a
language-level concurrency primitive. A coroutine is launched in a
`CoroutineScope` and runs until completion or cancellation. The model is
**structured concurrency**: every coroutine has a parent scope; the scope's
lifetime bounds the children's lifetimes; child failures propagate to the
parent unless suppressed by a `SupervisorJob`.

### `GlobalScope.launch` — the structured-concurrency escape hatch

`GlobalScope` is a process-lifetime singleton. A coroutine launched in
`GlobalScope` is not a child of any caller-defined scope; if the network hangs,
the coroutine hangs forever; uncaught exceptions hit the platform's last-resort
handler (on Android, the process crashes).

Elizarov's position
(`elizarov.medium.com/the-reason-to-avoid-globalscope-835337445abc`) is that
`GlobalScope` is a "delicate API" requiring opt-in
(`@OptIn(DelicateCoroutinesApi::class)`); the kotlinx.coroutines 1.5 release
formalized the warning. Acceptable uses are rare — top-level background
processes with no parent lifecycle.

### `runBlocking` inside coroutine context — deadlock potential

`runBlocking` runs a coroutine on the current thread and *blocks the thread
until completion*. Designed for bridging blocking and suspending code (tests,
`main`). Calling `runBlocking` *from within a coroutine* blocks the coroutine's
dispatcher thread; if the block then calls a suspend function dispatched on
the same thread, the dispatcher cannot schedule new work — **deadlock**.

Concrete scenarios in kotlinx.coroutines issue tracker: 1397 (unintuitive
deadlock with specified dispatcher), 2448 (Android `Main.immediate` nested-
context lock), 3204 (other coroutines dispatched on the blocked calling
thread).

Rule: **never call `runBlocking` inside a `suspend` function or coroutine
context.** Use `coroutineScope { }` instead.

### `Thread.sleep` inside a suspending function

`Thread.sleep(N)` blocks the *thread*; `delay(N)` suspends the *coroutine*
(releasing the dispatcher thread). Calling `Thread.sleep` inside `suspend`
ties up the dispatcher; if enough concurrent calls accumulate, the
dispatcher pool exhausts and every other coroutine on it stalls.

```kotlin
suspend fun bad(): String { Thread.sleep(1000); return "done" }  // BAD
suspend fun good(): String { delay(1000); return "done" }        // GOOD
```

Most common coroutine performance footgun on JVM. Silently destroys
throughput; no crash.

### `withContext(Dispatchers.IO)` and dispatcher discipline

Standard pattern for "blocking call I cannot rewrite":

```kotlin
suspend fun fetchUser(id: Long): User = withContext(Dispatchers.IO) {
    blockingHttpCall(id)
}
```

`Dispatchers.IO` (default 64 threads, blocking I/O); `Dispatchers.Default`
(CPU pool, small); `Dispatchers.Main` (Android UI). Common mistakes:

1. Blocking JDBC/HTTP/file I/O on `Dispatchers.Default` — exhausts the small
   CPU pool.
2. Blocking I/O on `Dispatchers.Main` (Android) — UI freeze, ANR.
3. `withContext(Dispatchers.IO)` inside already-IO-dispatched coroutine —
   pointless context switch.

### `CancellationException` swallowing — the silent killer

Cancellation is cooperative: the parent scope sets a flag; suspending
functions check it and throw `CancellationException`. If user code wraps the
cancellation point in `try { } catch (e: Exception)`, the catch swallows
`CancellationException` (it is a subclass of `Exception`). The `Job` is
cancelled but execution continues past the catch — DB writes, network calls,
UI updates after cancellation. This is the "zombie coroutine" state.

```kotlin
// Bug
launch {
    try { delay(1000); riskyOperation() }
    catch (e: Exception) { log.error("failed", e) }  // swallows cancellation
    cleanup()  // still runs
}

// Fix: catch and rethrow CancellationException first
launch {
    try { delay(1000); riskyOperation() }
    catch (e: CancellationException) { throw e }
    catch (e: Exception) { log.error("failed", e) }
}

// Or use ensureActive() defensively
launch {
    try { delay(1000); riskyOperation() }
    catch (e: Exception) { ensureActive(); log.error("failed", e) }
}
```

Sources: `kotlinlang.org/docs/exception-handling.html`,
`kt.academy/article/cc-cancellation`.

### `SupervisorJob` vs `Job` — child failure isolation

`Job()` propagates child failure (one child fails → parent cancels siblings).
`SupervisorJob()` isolates failures (one child's failure does not cancel
siblings). Footgun: developers reach for `SupervisorJob` to "make failures
less disruptive" without understanding it also requires an explicit
`CoroutineExceptionHandler`; otherwise child failures go to the thread's
default uncaught-exception handler.

### Audit recipe

1. Grep `GlobalScope.launch` / `GlobalScope.async`; require
   `@OptIn(DelicateCoroutinesApi::class)` + justification.
2. Grep `runBlocking { }` inside `suspend`; replace with `coroutineScope { }`.
3. Grep `Thread.sleep` inside `suspend`; replace with `delay`.
4. Grep `catch (e: Exception)` / `catch (e: Throwable)` in coroutine bodies;
   confirm `CancellationException` rethrow or `ensureActive()`.
5. Grep `SupervisorJob()`; confirm a `CoroutineExceptionHandler` is attached.
6. Cross-link `race_conditions_concurrency_expertise.md` for shared-state JMM.

---

## 8. `==` vs `===` and Data Class Equality

In Kotlin: `a == b` calls `a.equals(b)`; `a === b` is reference identity.
Reverse of Java; eliminates one Java footgun, introduces inverse confusion
for cross-language developers.

`data class` auto-generates `equals()`, `hashCode()`, `toString()`, `copy()`,
and `componentN()` from the primary constructor properties. Properties
declared in the class body are NOT included.

```kotlin
data class User(val id: Long, val email: String) {
    var lastLogin: Instant? = null  // NOT in equals/hashCode
}
```

### Mutable-data-class-as-map-key

If a primary-constructor property is `var`, the instance's hash changes
when mutated. After insertion as a HashMap key, mutating the property
breaks the lookup invariant.

```kotlin
data class Key(var id: Long)
val map = mutableMapOf<Key, String>()
val k = Key(1L); map[k] = "one"
k.id = 2L                  // hash changes
map[k]      // null: lookup misses
map[Key(1L)]  // null: orphaned in bucket
```

Fix: declare all `data class` properties as `val`. Effective Kotlin Item 43
(`kt.academy/article/ek-hashcode`) names the rule explicitly.

### Inheritance restrictions

`data class` cannot extend another `data class`; cannot be `open`,
`abstract`, `sealed`, or `inner`. Auto-generated `equals()` cannot reason
about polymorphic subclass equality. Developers moving from Lombok `@Data`
hit the restriction.

### Java interop

Java consumers see `getId()`, `setId()` (only for `var`), `copy(...)`,
`componentN()`, and the auto-generated `equals`/`hashCode`. A Java caller
mutating a `data class` `var` exhibits the same map-key bug.

### Audit recipe

1. Confirm all primary-constructor properties are `val`.
2. For any `var`-bearing `data class`, document why and verify it is never
   used as a hash key. Hand-roll equals/hashCode on immutable fields if
   mutability is required.
3. Make the mutability constraint explicit in Java-caller docs.

Sources: `kt.academy/article/ek-hashcode`,
`baeldung.com/kotlin/equals-hashcode-generator`.

---

## 9. Type Erasure and `reified` Type Parameters

Kotlin compiles to JVM bytecode, which erases generic type parameters at
compile time. At runtime `List<String>` and `List<Int>` are both `List`;
reflection cannot recover the type argument.

```kotlin
fun <T> Gson.fromJson(s: String): T = fromJson(s, T::class.java)
// ERROR: Cannot use 'T' as reified type parameter
```

The Kotlin solution is `inline` functions with `reified` type parameters:

```kotlin
inline fun <reified T> Gson.fromJson(s: String): T = fromJson(s, T::class.java)
val user: User = gson.fromJson(json)  // T inferred and preserved
```

`inline` inlines the body at each call site; `reified` substitutes `T` with
the concrete type, materializing type info into bytecode.

### Restrictions and footguns

1. **`reified` requires `inline`.** Non-inline functions cannot use it.
2. **Reified inline functions are not callable from Java.** Java has no inlining
   primitive; bytecode emits a runtime-error stub.
3. **Inline bodies replicate at every call site.** Binary size grows; the
   compiler warns when an inline function has no inlinable function
   parameters and no reified type parameters.
4. **`KClass<T>` vs `Class<T>`.** `T::class` is `KClass<T>`; `T::class.java`
   is `Class<T>`. `kotlin-reflect` uses `KClass`; many Java APIs expect
   `Class`. Frequent source of "Kotlin reflection compiles, Java reflection
   fails at runtime" bugs.

### Audit recipe

1. For public APIs accepting `Class<T>`, evaluate a `reified` inline
   alternative.
2. For `inline` `reified` functions, confirm the body is small; use
   `noinline` on lambda params that need to be referenced (not just called).
3. Confirm no Java callers depend on `reified` inline functions.

Sources: `baeldung.com/kotlin/reified-functions`,
`kotlinlang.org/docs/inline-functions.html`.

---

## 10. Collection Operations and Lazy Sequences

Kotlin distinguishes `Iterable<T>` (eager, default) from `Sequence<T>`
(lazy). `Iterable<T>` operations (`map`, `filter`) allocate a new collection
per stage. `Sequence<T>` defers until a terminal op and walks
element-by-element.

```kotlin
listOf(1, 2, 3, 4, 5).map { it * 2 }.filter { it > 4 }.first()
// allocates two intermediate ArrayLists

listOf(1, 2, 3, 4, 5).asSequence().map { it * 2 }.filter { it > 4 }.first()
// only the first matching element is processed
```

### When lazy wins, when eager wins

Lazy wins: large collection, short-circuiting terminal (`first`, `take`,
`find`), many pipeline stages. Eager wins: small collection (overhead
dominates), full-traversal terminal, 1-2 stages. Chris Banes's benchmark
(`chrisbanes.me/posts/use-sequence/`) measures ~9% sequence overhead on
short pipelines + small collections.

### `filter then map` vs `map then filter`

```kotlin
list.map { transform(it) }.filter { it.valid }       // transform runs N times
list.filter { precondition(it) }.map { transform(it) }  // transform runs K ≤ N times
```

If `transform` is expensive, filter-first is faster. If `transform` can fail
on `!precondition` inputs, filter-first is also semantically required.

### `Iterable<T>` reuse vs `Iterator<T>` single-use

`Iterable<T>` produces a fresh iterator per `iterator()` call. `Iterator<T>`
is single-use; `sequence { yield ... }` creates a fresh iterator per
iteration, re-running its block; re-iteration on a
`constrainOnce()` sequence throws `IllegalStateException`. Footgun:
re-iterating a yield-based generator repeats side effects.

### Mutability of collections

`List<T>`, `Set<T>`, `Map<K, V>` are read-only *views* — the underlying
storage may be mutable, and another holder can mutate it behind the
read-only reference.

```kotlin
val mutable: MutableList<Int> = mutableListOf(1, 2, 3)
val readOnly: List<Int> = mutable
mutable.add(4)
println(readOnly)  // [1, 2, 3, 4] — view sees mutation
```

Defensive pattern: `.toList()` at trust boundaries.

Sources: `kotlinlang.org/docs/sequences.html`, `kt.academy/article/ek-sequence`.

---

## 11. Android-Specific Kotlin Footguns

Sketches the Android Kotlin surface; full attack catalog in
`mobile_security_expertise.md` §7.

### Activity lifecycle and coroutine cancellation

Coroutines launched from an Activity must be canceled on destroy; otherwise
they leak the Activity reference. Discipline primitives:

- **`lifecycleScope`** — extension on `LifecycleOwner`; coroutines cancel at
  `DESTROYED`.
- **`viewModelScope`** — extension on `ViewModel`; cancels when the
  `ViewModel` is cleared (after Activity destroy AND config-change complete).
- **`repeatOnLifecycle(STARTED) { ... }`** — restarts at `STARTED`, cancels
  below.

Footgun: `GlobalScope.launch` or `CoroutineScope(Dispatchers.IO).launch`
inside an Activity leaks the Activity. Vivo's
"Easy Coroutines in Android: viewModelScope" is the canonical guidance.

### Parcelable codegen and deserialization

`@Parcelize` auto-generates `writeToParcel` / `createFromParcel` against the
same Android Parcel wire format Java uses. Parcel deserialization is a
documented attack-surface class:

- **CVE-2017-13315 (EvilParcel)** — write/read shape mismatches produce
  data boundary misalignment.
- **CVE-2022-20452 (LeakValue, Bednarski)** — privilege escalation via
  `LazyValue` and `Parcel` after `recycle()`.
- **CVE-2023-20963** — mismatching parcel/unparcel logic for WorkSource;
  Project Zero RCA.

Footgun: `@Parcelize` automates the boilerplate but cannot protect against
mismatched write/read shapes across versions. Treat the Parcel format as
versioned protocol. See
`securitylab.github.com/resources/android-deserialization-vulnerabilities/`
and the Black Hat EU 2022 talk "Android parcels: the bad, the good and the
better."

### Room database and `@RawQuery`

Room's `@Query` parses SQL at compile time and binds parameters safely.
`@RawQuery` is the escape hatch — no validation, attacker-influenced strings
in the SQL produce injection.

```kotlin
@Query("SELECT * FROM users WHERE email = :email")  // SAFE
fun findByEmail(email: String): User

@RawQuery  // UNSAFE if caller concatenates user input
fun searchByPattern(query: SupportSQLiteQuery): List<User>
```

### `LiveData` vs `StateFlow`

`LiveData.observe()` auto-unregisters at `STOPPED`; collecting `StateFlow`
does not. Use `repeatOnLifecycle(STARTED) { flow.collect { } }` for
lifecycle-aware StateFlow. Footgun: bare
`lifecycleScope.launch { flow.collect { } }` keeps collecting when the UI
is not visible — wasted battery and possible races with UI updates.

`StateFlow` requires an initial value (forces thinking about "no data yet");
`SharedFlow` is the broadcast/event analog (no replay by default).

### Compose `remember { ... }` keys

Footguns:

1. **Forgetting `remember`** — state resets on every recomposition.
2. **Wrong keys** — irrelevant keys cause excessive recomputation; missing
   keys cause stale state.
3. **List items keyed by position** — reordering loses per-item state. Use
   `key(itemId) { }` for identity-based keys.
4. **Backwards writes** — writing `MutableState` during composition that
   reads the same state causes infinite recomposition. Symptom: screen
   never settles + CPU at 100%.

Sources: `developer.android.com/develop/ui/compose/state`,
`developer.android.com/develop/ui/compose/performance/bestpractices`.

### Intent attacks (cross-link)

`Intent.getStringExtra("key")` is platform-typed `String!`. Contents are
attacker-controllable when the receiving component is `exported=true`.
See `mobile_security_expertise.md` §7.

---

## 12. Kotlin-on-Server (Ktor / Spring) Specifics

### Ktor

Ktor is built natively on coroutines; handlers are `suspend` functions.
Footguns:

1. **Blocking calls in handlers.** Stalls dispatcher thread. Use
   `withContext(Dispatchers.IO)` for blocking JDBC/HTTP.
2. **Connection pool exhaustion.** HikariCP default 10 connections is small
   for heavy DB workloads.
3. **Async work outside structured concurrency.** `GlobalScope.launch` from
   a handler unparents work from the request; client disconnect doesn't
   cancel it.

### Spring Boot Kotlin + JPA

JPA expects non-final classes, parameterless constructors, mutable
properties (Hibernate reflection). Kotlin defaults conflict:

- Kotlin classes are `final` by default — use `kotlin-allopen` plugin.
- No parameterless constructor — use `kotlin-noarg`
  (`org.jetbrains.kotlin.plugin.jpa`).
- `data class` properties default to `val` — Hibernate needs `var` for
  lazy loading.

Recent regression: Spring Boot 3.4.0 + Kotlin JPA + `@Version` throws
`EntityExistsException: detached entity passed to persist` with
`hibernate-core:6.6.2`. Downgrade to 6.5.3 resolves. Issue 3696 in
`spring-projects/spring-data-jpa`.

`data class` + JPA footgun: auto-generated `toString`/`equals`/`hashCode`
traverses all properties including lazy associations — calling `toString`
on a partially-loaded entity triggers extra queries (N+1 from a log line).

### Jackson + Kotlin null safety

Jackson alone does not honor Kotlin null safety: JSON `null` into a
non-null property succeeds, leaving the property holding `null`. The fix
is `jackson-module-kotlin`:

```kotlin
val mapper = jacksonObjectMapper()  // or: ObjectMapper().registerKotlinModule()
```

The module throws `MissingKotlinParameterException` on null into non-null.
Easy to forget when bootstrapping a Spring Boot Kotlin project; without
it, Jackson silently produces invalid Kotlin state.

### Server-side blocking-call discipline

```kotlin
suspend fun getUser(id: Long): User = withContext(Dispatchers.IO) {
    userRepository.findById(id)  // blocking JDBC
}
```

Every `@Service` doing JPA/JDBC/file I/O from a `suspend` WebFlux handler
must wrap in `withContext(Dispatchers.IO)`. Spring's `R2dbcRepository` is
the reactive-native alternative.

---

## 13. Cryptographic API (JCA Inheritance)

Kotlin's crypto API is `javax.crypto` — JCA, identical to Java. Full
catalog in `java_footguns_expertise.md` §8 and `cryptography_expertise.md`.
Key items that propagate:

1. **ECB by default.** `Cipher.getInstance("AES")` returns `AES/ECB`.
   Always specify `AES/GCM/NoPadding` or `AES/CBC` with authenticated MAC.
2. **`SecretKeySpec` with raw password.** `SecretKeySpec(password.toByteArray(), "AES")`
   uses raw bytes as key. Correct: `PBKDF2WithHmacSHA256` or Argon2 with
   high iteration count.
3. **`SecureRandom` not seeded.** JVM ≥ 8 OK; older JVMs and some Android
   versions had thread-state-derived predictable seeds.
4. **`MessageDigest.getInstance("MD5")` / `SHA-1`** — broken hash
   primitives still in the API.

### `kotlinx.serialization` + crypto protocols

`kotlinx.serialization` generates a serializer per class at compile time;
safer than Jackson reflection. Footgun: `kotlinx-serialization-json`
supports polymorphism via `@SerialName` / `@JsonClassDiscriminator`. The
discriminator is attacker-controllable; an `@Polymorphic` sealed hierarchy
without an explicit allowlist is the polymorphic-deserialization surface
analog to Jackson's `@JsonTypeInfo` (see `deserialization_expertise.md`
§3). Restrict to `sealed` hierarchies, whose direct subclasses are fixed by
package and module.

### `Random` vs `SecureRandom`

`kotlin.random.Random` is non-cryptographic. `java.security.SecureRandom`
is. Footgun: developers reach for `kotlin.random.Random` for CSRF tokens,
password-reset tokens, session IDs — values become predictable.

---

## 14. Build and Supply Chain

### Gradle Kotlin DSL (`build.gradle.kts`)

`build.gradle.kts` is Kotlin source code, compiled and executed by Gradle at
configuration time. Anything a developer can write in Kotlin is permissible:
network calls, file I/O, subprocess invocation, system property reads. The
configuration phase runs before any task; even `gradle help` triggers
configuration of every module.

Implications:

1. **`./gradlew` on an untrusted repo runs `build.gradle.kts`** — including
   any malicious code. Gradle documents this: "Inspect the build scripts and any
   contributed code before running any tasks or importing a project into the IDE."
2. **Plugins are arbitrary Kotlin.** `id("com.x.plugin") version "1.0"`
   downloads from plugin portal / Maven Central; the plugin's `apply` runs
   with full Gradle authority at config time.
3. **Wrapper attacks.** `gradle-wrapper.jar` is checked into the repo and
   executed by `./gradlew`. January 2023 MinecraftOnline incident
   demonstrated active wrapper-JAR exploitation.

Mitigations: dependency verification with checksums and signatures
(`docs.gradle.org/current/userguide/dependency_verification.html`), plugin
pinning, wrapper-JAR review on every PR. Cross-link
`cicd_supply_chain_expertise.md` §5.

### Maven Central and KSP

Kotlin libraries publish to Maven Central (default), GitHub Packages, and
JetBrains repos. Same trust model as `java_footguns_expertise.md` §14 —
namespace ownership, signing, dependency-confusion all apply.

KSP (Kotlin Symbol Processing) plugins are compile-time processors. Untrusted
KSP plugins can generate malicious source into the build output, exfiltrate
the consuming codebase's AST, or break the build (DoS). Same trust shape
as Maven plugins: pin versions, verify checksums, audit before adoption.
KSP2 default since 2.0.0; API and trust model unchanged.
`kotlinlang.org/docs/ksp-overview.html`, `github.com/google/ksp`.

---

## 15. Detection Patterns

### Semgrep patterns

Kotlin Semgrep coverage is mature. Sketches below; cross-link the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview).

```yaml
rules:
  - id: kotlin-lateinit-var
    pattern: lateinit var $X : $T
    message: lateinit reading before init throws UninitializedPropertyAccessException. Prefer `by lazy` or constructor injection.
    severity: WARNING
    languages: [kotlin]

  - id: kotlin-not-null-assertion
    pattern: $X!!
    message: `!!` suppresses null safety. Prefer `?:`, `requireNotNull`, `checkNotNull`.
    severity: WARNING
    languages: [kotlin]

  - id: kotlin-global-scope
    pattern-either:
      - pattern: GlobalScope.launch(...) { ... }
      - pattern: GlobalScope.async(...) { ... }
    message: GlobalScope bypasses structured concurrency. Use a caller-scoped CoroutineScope.
    severity: WARNING
    languages: [kotlin]

  - id: kotlin-runblocking-in-suspend
    patterns:
      - pattern: runBlocking { ... }
      - pattern-inside: |
          suspend fun $F(...) { ... }
    message: runBlocking inside suspend can deadlock the dispatcher. Use coroutineScope { } instead.
    severity: ERROR
    languages: [kotlin]

  - id: kotlin-thread-sleep-in-suspend
    patterns:
      - pattern: Thread.sleep(...)
      - pattern-inside: |
          suspend fun $F(...) { ... }
    message: Thread.sleep blocks the dispatcher thread. Use delay(...).
    severity: ERROR
    languages: [kotlin]

  - id: kotlin-data-class-var
    pattern: data class $C(..., var $X: $T, ...)
    message: Mutable data-class property breaks equals/hashCode invariants when used as a hash key. Use val.
    severity: WARNING
    languages: [kotlin]

  - id: kotlin-class-forname-user-input
    patterns:
      - pattern: Class.forName($X)
      - pattern-not: Class.forName("...")
    message: Class.forName with non-literal argument can load attacker-controlled class. Use an allowlist.
    severity: ERROR
    languages: [kotlin]

  - id: kotlin-cipher-no-mode
    pattern-either:
      - pattern: Cipher.getInstance("AES")
      - pattern: Cipher.getInstance("DES")
      - pattern: Cipher.getInstance("3DES")
    message: Cipher.getInstance with no mode defaults to ECB. Specify GCM/CBC with authenticated MAC.
    severity: ERROR
    languages: [kotlin]

  - id: kotlin-room-rawquery
    pattern: |
      @RawQuery
      fun $F(...): $T
    message: @RawQuery skips compile-time SQL validation. Prefer @Query with bound parameters.
    severity: WARNING
    languages: [kotlin]
```

### detekt, Android Lint, SonarKotlin

- **`detekt`** (`detekt.dev`): `UnsafeCallOnNullableType` (`!!`),
  `GlobalCoroutineUsage`, `SleepInsteadOfDelay`,
  `SuspendFunWithCoroutineScopeReceiver`. Configure as a Gradle
  pre-commit hook; baseline existing issues, gate new at error.
- **Android Lint**: `ExportedPreferenceActivity`, `WorldReadableFiles`,
  `ParcelClassLoader`,
  `SetJavaScriptEnabled`. Integrates with Gradle.
- **SonarKotlin** (`github.com/SonarSource/sonar-kotlin`,
  `rules.sonarsource.com/kotlin/`): org-wide code-quality + security
  rules beyond detekt's per-rule focus.

---

## 16. Defensive Checklist and Variant Analysis

### 12-item checklist (Kotlin-specific)

1. **Eliminate `!!` from production Kotlin code.** Replace with `?:`, `?.let`,
   `requireNotNull`, or `checkNotNull` with descriptive messages.
2. **Replace `lateinit` with `by lazy` or constructor injection** where
   the framework's init guarantee is not absolutely watertight.
3. **Treat every Java-interop boundary as a platform-type elimination
   point** — assign explicitly to `T` or `T?` and let the inserted
   assertion or explicit nullable handling make the choice visible.
4. **Ban `GlobalScope.launch` outside `@OptIn(DelicateCoroutinesApi)`
   gated call sites** that have a documented justification.
5. **Ban `runBlocking` inside `suspend` functions** and inside any
   non-test, non-main code path.
6. **Ban `Thread.sleep` inside `suspend` functions.** Use `delay`.
7. **Audit every `try { } catch (e: Exception)` in coroutine bodies** for
   `CancellationException` rethrow or `ensureActive()`.
8. **Declare every `data class` property as `val`** unless documented
   otherwise; never use a `var`-containing `data class` as a map key.
9. **Use `reified` for type-checking generic functions.** Avoid passing
   `Class<T>` parameters when an inline alternative is available.
10. **Add `jackson-module-kotlin`** to every Kotlin + Jackson project.
    Audit for `MissingKotlinParameterException` in tests.
11. **Use Room `@Query` with bound parameters.** Audit every `@RawQuery`.
12. **Apply Android lifecycle-aware coroutine scopes** (`viewModelScope`,
    `lifecycleScope`, `repeatOnLifecycle`) on Android. Ban
    `CoroutineScope(Dispatchers.IO).launch` from Activity/Fragment code.

### Variant analysis

Kotlin's footgun catalog varies by platform target:

**Kotlin/JVM.** All §2-§14 footguns apply, plus full Java inheritance from
`java_footguns_expertise.md`. Dominant target for server and Android.

**Kotlin/Android.** JVM + §11 (lifecycle, Parcel, Room, Compose, Intent,
deep links). Cross-link `mobile_security_expertise.md` §7.

**Kotlin/Native.** LLVM-compiled native; no JVM safety net.
- No `Class.forName` or JNDI — polymorphic-deserialization gadget
  surface shrinks dramatically.
- Memory: ARC, transitioning to traced GC (1.7.20+). Cycles and leaks
  possible.
- No JCA — crypto primitives come from third-party libraries (no ECB
  default, but no default secure primitive either).
- `@Throws` mandatory for Swift/ObjC interop; omission crashes the
  Swift bridge on exception.

**Kotlin/JS.** Different runtime:
- `number` is IEEE 754 double; `Long` is emulated and slow. Integer-
  overflow semantics differ from JVM.
- Reflection limited; `KClass.simpleName` works, full type-info doesn't.
- No JCA; use WebCrypto.
- `external` declarations bypass the type system, producing platform-
  type-like uncertainty.

**Kotlin/Wasm.** Beta since 2.2.20; runtime distinct from JVM and JS. Treat
production deployments as research-stage.

**Compose Multiplatform.** Composables shared across Android, desktop,
iOS (Kotlin/Native). State discipline (`remember`, `mutableStateOf`,
recomposition keys) is identical; underlying lifecycle differs (no
Android Activity on desktop). Confirm `LifecycleOwner` per platform.

Cross-link `code_review_expertise.md` for audit methodology.

---

## 17. References

### Foundational Kotlin design

- Kotlin Language Specification: `kotlinlang.org/spec/kotlin-spec.html`
- KEEP (Kotlin Evolution and Enhancement Process):
  `github.com/Kotlin/KEEP`
- Kotlin Foundation: `kotlinfoundation.org`
- JetBrains Kotlin blog: `blog.jetbrains.com/kotlin/`
- Andrey Breslav bio: `abreslav.com/bio`
- Roman Elizarov on coroutines:
  `elizarov.medium.com`,
  `resources.jetbrains.com/storage/products/kotlinconf2017/slides/2017+KotlinConf+-+Introduction+to+Coroutines.pdf`
- Hadi Hariri / Talking Kotlin: `talkingkotlin.com`

### Null safety, platform types

- Null safety: `kotlinlang.org/docs/null-safety.html`
- Java interop / platform types: `kotlinlang.org/docs/java-interop.html`,
  `kotlinlang.org/docs/java-to-kotlin-nullability-guide.html`
- Effective Kotlin Item 3 (Moskała):
  `kt.academy/article/ek-platform-types`
- Effective Kotlin Item 43 (hashCode contract):
  `kt.academy/article/ek-hashcode`
- Baeldung Kotlin: `baeldung.com/kotlin`
- JSpecify: `jspecify.dev`

### Coroutines and structured concurrency

- Coroutines basics: `kotlinlang.org/docs/coroutines-basics.html`,
  `github.com/Kotlin/kotlinx.coroutines`
- Elizarov, "The reason to avoid GlobalScope":
  `elizarov.medium.com/the-reason-to-avoid-globalscope-835337445abc`
- "GlobalScope Marked as Delicate" (Coroutines 1.5):
  `blog.jetbrains.com/kotlin/2021/05/kotlin-coroutines-1-5-0-released/`
- Exception handling: `kotlinlang.org/docs/exception-handling.html`
- Cancellation: `kotlinlang.org/docs/cancellation-and-timeouts.html`,
  `kt.academy/article/cc-cancellation`
- "How I Fell in Kotlin's RunBlocking Deadlock Trap" (Cooper):
  `medium.com/better-programming/how-i-fell-in-kotlins-runblocking-deadlock-trap-and-how-you-can-avoid-it-db9e7c4909f1`

### Android Kotlin

- "Easy Coroutines in Android: viewModelScope" (Vivo):
  `medium.com/androiddevelopers/easy-coroutines-in-android-viewmodelscope-25bffb605471`
- Lifecycle-aware coroutines:
  `developer.android.com/topic/libraries/architecture/coroutines`
- StateFlow / SharedFlow:
  `developer.android.com/kotlin/flow/stateflow-and-sharedflow`
- Compose: `developer.android.com/develop/ui/compose/state`,
  `developer.android.com/develop/ui/compose/performance/bestpractices`,
  `developer.android.com/develop/ui/compose/side-effects`
- Android SQL injection:
  `developer.android.com/topic/security/risks/sql-injection`
- Android unsafe deserialization:
  `developer.android.com/privacy-and-security/risks/unsafe-deserialization`
- GitHub Security Lab Android deserialization:
  `securitylab.github.com/resources/android-deserialization-vulnerabilities/`
- "Android parcels: the bad, the good and the better" (Black Hat EU 2022):
  `i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Ke-Android-Parcels-Introducing-Android-Safer-Parcel.pdf`
- CVE-2023-20963 RCA (Project Zero):
  `googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-20963.html`
- LeakValue / CVE-2022-20452 (Bednarski):
  `github.com/michalbednarski/LeakValue`
- "ONE CLASS TO RULE THEM ALL" (Peles & Hay, WOOT '15):
  `usenix.org/system/files/conference/woot15/woot15-paper-peles.pdf`

### Server-side Kotlin

- Ktor: `ktor.io`, `github.com/ktorio/ktor`
- Spring Data JPA with Kotlin:
  `blog.jetbrains.com/idea/2026/03/using-spring-data-jpa-with-kotlin/`
- Spring Boot 3.4 Kotlin JPA regression:
  `github.com/spring-projects/spring-data-jpa/issues/3696`
- jackson-module-kotlin:
  `github.com/FasterXML/jackson-module-kotlin`

### Build, supply chain

- Gradle Kotlin DSL: `docs.gradle.org/current/userguide/kotlin_dsl.html`
- Dependency verification:
  `docs.gradle.org/current/userguide/dependency_verification.html`
- Wrapper attack report: `blog.gradle.org/wrapper-attack-report`
- Gradle security: `blog.gradle.org/category/security`
- KSP: `kotlinlang.org/docs/ksp-overview.html`, `github.com/google/ksp`
- KAPT: `kotlinlang.org/docs/kapt.html`

### Static analysis

- detekt: `detekt.dev`, `github.com/detekt/detekt`
- SonarKotlin: `github.com/SonarSource/sonar-kotlin`,
  `rules.sonarsource.com/kotlin/`
- Android Lint:
  `googlesamples.github.io/android-custom-lint-rules/checks/list.md.html`

### OWASP MASVS / MASTG

`mas.owasp.org/MASVS/`, `mas.owasp.org/MASTG/`, `mas.owasp.org/`

### Cross-language deserialization

For non-Kotlin deserialization (Java Serialization, Jackson polymorphic
type-info, SnakeYAML, .NET BinaryFormatter, pickle, unserialize,
Marshal), see `deserialization_expertise.md`.

### Tooling and audit-vendor research

- Trail of Bits Testing Handbook: `appsec.guide`,
  `github.com/trailofbits/skills`,
  `blog.trailofbits.com/categories/audits/`
- Oversecured: `blog.oversecured.com`
- Hacktive Security Android deserialization deep dive:
  `hacktivesecurity.com/blog/2025/03/13/android-deserialization-deep-dive/`

---

## End notes

Kotlin is structurally distinguished from sibling footgun docs by the
*layered* catalog: a relatively safe-by-default Kotlin surface (null
safety, immutability, structured concurrency, exhaustive `when`) stacked
on top of an unsafe-by-default Java/JVM surface (ObjectInputStream, JNDI,
JCA defaults, reflective `Class.forName`). The audit posture: confirm
discipline at the Kotlin layer (§2-§12) AND inherit every Java-footgun
control from `java_footguns_expertise.md`. Both layers ship together;
both must be reviewed together.
