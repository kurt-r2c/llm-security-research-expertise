# Scala Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Martin Odersky, Adriaan Moors, Lukas Rytz, Sébastien Doeraene, Travis Brown, Jamie Allen, John A. De Goes, the Lightbend / Akka security advisory record, and the Trail of Bits / Snyk Scala / Akka audit corpora

> **Currency marker:** Last refreshed 2026-05-14. This is the Scala instance in the
> language-specific *behavioral footgun* class and should be read alongside the JVM-shared
> parent (`java_footguns_expertise.md`), the JVM-sibling deepening (`kotlin_footguns_expertise.md`,
> parallel deepening this shift), the manual-audit methodology (`code_review_expertise.md`),
> the cross-language race-condition surface (`race_conditions_concurrency_expertise.md`), the
> JVM-shared supply-chain surface (`cicd_supply_chain_expertise.md`), the cross-language gadget
> tradition (`deserialization_expertise.md`), and the rule-design tradition
> (`semgrep_rule_authoring.md`).

> **Researchers:**
> - **Martin Odersky** — Professor at EPFL; inventor and lead designer of Scala (1.0 through 3.x);
>   previously co-author of Generic Java and the Pizza language; head of the Programming Methods
>   Laboratory (LAMP) at EPFL; co-founder of Lightbend (formerly Typesafe); ACM SIGPLAN
>   Programming Languages Achievement Award. Sources: `people.epfl.ch/martin.odersky`,
>   `actu.epfl.ch/news/to-create-scala-we-could-start-from-scratch-4/`.
> - **Adriaan Moors** (@adriaanm) — Scala Tech Lead at Lightbend since 2012; contributed
>   type-constructor polymorphism (2.7), the pattern matcher rewrite (2.10), standard-library
>   modularization (2.11), Single Abstract Method types (2.12), and many type-checker
>   improvements; post-doc in Odersky's lab before joining Typesafe. Source:
>   `adriaanm.github.io`.
> - **Lukas Rytz** (@lrytz) — Compiler engineer and lead of the Lightbend Scala team;
>   designed named and default arguments in Scala 2.8; bytecode optimizer for Scala 2.12 and
>   2.13; doctoral research on effect systems for non-pure functional languages. Sources:
>   `lrytz.github.io`, `scala-lang.org/blog/new-governance.html`.
> - **Sébastien Doeraene** (@sjrd) — Author of Scala.js (the JavaScript-targeting Scala
>   dialect); executive director of the Scala Center; LAMP lecturer at EPFL; Ph.D. on
>   cross-platform language design under Odersky. Sources: `lampwww.epfl.ch/~doeraene/`,
>   `scala.epfl.ch`.
> - **Travis Brown** (@travisbrown) — Author/maintainer of `circe` (JSON for Scala); top
>   contributor to Typelevel `cats`. Source: `github.com/travisbrown`, `index.scala-lang.org/circe`.
> - **Jamie Allen** — Author of *Effective Akka* (O'Reilly, 2013); former Director of Consulting
>   at Typesafe; long-time Akka practitioner since 2009; the canonical English-language
>   primer on actor-system anti-patterns in production. Source:
>   `oreilly.com/library/view/effective-akka/9781449360061/`.
> - **John A. De Goes** (@jdegoes) — Founder of Ziverge; creator of the ZIO functional effect
>   system; vocal critic of `scala.concurrent.Future` cancellation gaps; ZIO 2.x evolution
>   lead. Source: `github.com/jdegoes`, `degoes.net/articles/zio-history`.
> - **Trail of Bits Scala / Akka audit corpus** — Institutional JVM-audit tradition (sbt
>   maintainership rests on the Scala Center, but supply-chain and tooling reviews appear in
>   the published canon); referenced together with the Lightbend / Akka advisory record at
>   `akka.io/security` and ASF's `LEGAL-714` BSL → Apache reversion clause. Sources:
>   `github.com/trailofbits/publications`, `blog.trailofbits.com/categories/audits/`.
> - **Snyk Scala / Akka CVE corpus** — Maintains the canonical public record of Scala-language
>   and Akka-toolkit CVEs (including CVE-2022-36944 LazyList RCE, CVE-2026-32948 sbt source-
>   dependency command injection). Source:
>   `security.snyk.io/package/maven/org.scala-lang%3Ascala-library`.
>
> **Cross-links to neighboring expertise docs:**
> - `java_footguns_expertise.md` — JVM parent; deserialization, JNDI, XML, reflection, JCA
>   primitives shared with Scala by inheritance
> - `kotlin_footguns_expertise.md` — JVM sibling; null-safety choices and coroutine primitives
>   diverge from Scala's `Option` + `Future` discipline
> - `code_review_expertise.md` — manual audit methodology that applies on top of these
>   primitives (Scala-specific candidate points: implicit conversion stacks, `Option.get`,
>   pattern-match catch-alls)
> - `race_conditions_concurrency_expertise.md` — JMM, happens-before, Future/IO/ZIO
>   concurrency surfaces
> - `cicd_supply_chain_expertise.md` — sbt + Coursier + Maven Central + Sonatype shared with
>   the JVM ecosystem
> - `deserialization_expertise.md` — Java/Jackson/SnakeYAML gadget chains apply directly to
>   Scala on the JVM
> - `semgrep_rule_authoring.md` — rule design for detecting these patterns at scale

---

## 1. The Behavioral-Footgun Framing

### Why "footgun" is the right primitive for Scala

A *cross-language bug class* (deserialization, command injection, SSRF) is defined by attacker
control over a semantic operation. A *behavioral footgun* is the inverse: a language-internal
primitive whose default behavior is unsafe regardless of attacker control. `ObjectInputStream.
readObject()` is both a deserialization sink AND a Java footgun, because the JVM ships it
with code-execution semantics enabled by default — and Scala compiles to that same JVM, so
every Java footgun applies to Scala by inheritance. **Start at `java_footguns_expertise.md`
and assume the entire surface there applies before reading anything below.**

What is *additionally* Scala's is the narrower set: implicit resolution, given/using, pattern
matching with extractors, lazy vals, case-class equality, variance, the `Future` / Cats
Effect / ZIO concurrency stack, the Akka actor model, the sbt build DSL. Many of these were
designed to *fix* a Java footgun; a subset introduced new ones. This doc covers the Scala-
specific surface plus the seams where Scala-on-JVM interaction creates compound footguns.

### The "Java-runtime, Haskell-influenced type system" tension

Scala runs on the JVM and must interoperate with arbitrary Java libraries (every `null`,
every `Throwable`, every `Serializable`, every classloader, every default-configured XML
parser). At the same time its type system is ML/Haskell-influenced: ADTs, pattern matching,
higher-kinded types, type-class derivation, monadic effect tracking, exhaustive case
analysis. Footguns live at the *seam* between those worlds:

- `Option[T]` is the idiom for nullable values, but Java returns `null`. Wrap returns with
  `Option(...)` (maps `null` to `None`); writing `Some(javaCall())` instead leaks `null` into
  `Some(null)` and downstream pattern matches NPE on dereference.
- `Future` is the async primitive on a JVM `ExecutionContext` (usually a `ForkJoinPool`). The
  same pool runs application code and library callbacks; a deadlock can arise when CPU-bound
  code awaits blocking code on the same EC.
- `case class` provides structural equality and a free `copy`, but Scala 2 case classes
  implement `java.io.Serializable` by default — every case class is a potential
  deserialization target wherever Java Serialization is in the pipeline.

### Implicits — most-distinctive feature AND most-distinctive footgun

Implicit resolution is the single largest source of behavioral surprise in Scala 2 codebases.
Implicit conversions and arguments are resolved at compile time by the type-inference
algorithm; resolution depends on imports, companion objects, and visible `implicit` members.
The same line of code can mean different things in two files that import different packages.
Scala 3 renamed to `given` / `using` / `extension` and made implicit conversions opt-in via
`import scala.language.implicitConversions` (partial fix; see §2).

The footgun lens asks: **what does Scala guarantee by default, what does it require opt-in?**

- `null` is assignable to any reference type — unless `-Yexplicit-nulls` (Scala 3, opt-in).
- `Option.get` is callable on `None` — no compiler check; partial.
- Pattern matches without `case _` warn (sealed) or `MatchError` at runtime (unsealed) —
  sealed is opt-in.
- `Future` does not support cancellation — Cats Effect / ZIO are opt-in alternatives.
- `case class` extends `java.io.Serializable` by default in Scala 2.
- sbt evaluates `build.sbt` as Scala code at build time — no sandbox.

**The language offers a safer alternative, but the unsafe primitive remains available and is
sometimes the default.** For Scala audit candidate-point selection (cross-link to
`code_review_expertise.md` §3): implicit-resolution sites, `.get` on `Option`/`Try`/`Either`,
`Await.result`, `case _` catch-alls in security-relevant matches, deserialization receivers.

### Scope

Fourteen numbered sections of Scala primitives plus detection patterns and a defensive
checklist. We do not duplicate Java's surface (`java_footguns_expertise.md`), cross-language
bug-class taxonomy (`deserialization_expertise.md`), or rule-authoring methodology
(`semgrep_rule_authoring.md`). Selection criterion: *probability a developer with no prior
Scala security context deploys this primitive in an unsafe configuration > ~50%.*

---

## 2. Implicits — Conversion, Argument Resolution, Scope Pollution

### The primitives (Scala 2)

Three forms the compiler treats as "implicit":

- `implicit val x: T = ...` — implicit value of type `T`; resolved when a function with an
  `implicit` parameter of type `T` is called without an explicit argument.
- `implicit def f(arg: S): T` (and the "view" `S => T` form) — *implicit conversion*. When
  the compiler finds an expression of type `S` in a position expecting `T`, it inserts `f(...)`.
- `implicit class C(arg: S) { ... }` (SIP-13) — class wrapping `S` with a synthesized
  conversion `S => C`; "extends" `S` with new methods.

Resolution: companion-object scope, package object scope, imported-identifier scope, lexical
scope, with specificity rules for ambiguity. See `docs.scala-lang.org/scala3/reference/contextual/`.

### Why implicits are the canonical Scala footgun

1. **Action at a distance.** `import some.package._` brings every `implicit` member into
   scope. If the package defines `implicit def stringToFoo(s: String): Foo`, any call taking
   `Foo` silently accepts a `String`. The compiler resolves without prompt; the only evidence
   is a different inferred type. The Scala 3 docs warn that "implicit conversions can have
   pitfalls if used indiscriminately"; the standard workaround is `import scala.language.
   implicitConversions`, which most codebases set globally.
2. **Operator semantics are not local.** Scala parses `a + b` as `a.+(b)`. An extension or
   conversion in scope can change `+` to do string concatenation or wrap an `Int` in a money
   type with different overflow semantics.
3. **Type inference depends on implicit search.** Importing a new package can introduce an
   additional conversion that shifts the inferred type and moves behavior across the call
   chain — the classic *"I imported a package and now my types are different"* bug.
4. **Type classes are encoded as implicit arguments.** Cats, ZIO, refined, http4s and most
   modern libraries encode polymorphism via implicit `MyTypeClass[T]` parameters. A missing
   instance is a compile error; an unexpected instance (someone defined one in scope) is a
   silent semantic change.

### Diamond resolution and stacking

Two implicits in scope for the same target type are disambiguated by *specificity*. The
rules interact with import shadowing in non-obvious ways: adding a more-specific `implicit
val foo = ...` can change resolution at a call site many files away. Scala 3's given-
prioritization spec tightens some rules but does not eliminate the surface.

### Scala 3's `given` / `using` cleanup

- `given foo: T = ...` replaces `implicit val foo: T = ...` — same scope rules.
- `using` on a parameter list (`def f(x: A)(using ctx: Context)`) replaces `implicit`
  parameters; more visible at call sites.
- `extension (s: String) def doubled = s + s` replaces implicit classes; clearer in errors.
- Implicit conversions require per-file `import scala.language.implicitConversions` and a
  `given Conversion[S, T]`; bare `implicit def` view form is deprecated.

A real improvement: operator overrides are harder, conversions require explicit opt-in,
`using` is visually distinguishable. But scope-based resolution is the same, and the
*type-class instance hijack* surface (importing a package brings in a different
`Ordering[Foo]` or `Codec[Bar]` than expected) is structurally unchanged. Source:
`docs.scala-lang.org/scala3/reference/contextual/relationship-implicits.html`.

### Audit pattern

Every `import` line is a potential implicit-scope change. Every call with an `implicit`/
`using` parameter is a potential type-class-instance hijack. Use `scalac -Xprint:typer` to
see what was resolved. WartRemover's `ImplicitConversion` wart flags definitions; see Section 13.

---

## 3. `null` Interop, `Option` Discipline, and the Java-Returns-`null` Seam

### Scala has `null`

Scala compiles to JVM bytecode, so `null` is a value of every reference type (`AnyRef`).
Every Java method returning a reference type can return `null`. Primitive types (`Int`,
`Long`, `Double`, etc.) extend `AnyVal` and cannot hold null — but their boxed forms
(`java.lang.Integer`) can.

### `Option[T]` as the idiomatic wrapper

`Option[T]` has subtypes `Some(value)` and `None`. The standard library provides:

- `Option(x)` — companion-apply mapping `null` to `None`; **safe wrap primitive** for
  ingesting potentially-null Java returns.
- `Option.empty[T]`, `Option.apply` aliases.

Recommended operations: `.map`, `.flatMap`, `.filter`, `.fold`, `.getOrElse(default)`,
pattern matching. The footgun is `Option.get`.

### `.get` on `None` throws

`Option.get` is the partial unwrap; calling on `None` raises
`java.util.NoSuchElementException: None.get`. Community consensus is anti-pattern; canonical
reference: `nrinaudo.github.io/scala-best-practices/partial_functions/option_get.html`. The
`Option` API documentation (`scala-lang.org/api/2.13.6/scala/Option.html`) lists `get` with
its throw behavior. `.get` is Scala's equivalent of Rust's `.unwrap()` or Kotlin's `!!`, but
unlike Rust's `unwrap`, `.get` looks like ordinary method invocation — no syntactic marker,
no compiler warning. WartRemover's `OptionPartial` wart and Scapegoat's `OptionGet`
inspection are the lint-time enforcement; neither is default-on.

### Compound footgun: `Option(javaCall())` vs `Some(javaCall())`

Intended:

```scala
val maybe: Option[String] = Option(someJavaApi.lookup(key))
```

Common bug:

```scala
val maybe: Option[String] = Some(someJavaApi.lookup(key))
```

The latter wraps `Some(null)`. The compiler does not flag (static type of `Some` is
`Some[String]` regardless of inner value). Downstream `case Some(s) => s.length` NPEs. One
of the most common Java-interop bugs and invisible to most linters. Cross-link to
`code_review_expertise.md` §4: every `Some(...)` whose inner expression crosses a Java
boundary is a candidate point.

### `Option.getOrElse` discipline

`getOrElse(default)` is **lazy in the default** — the by-name parameter only evaluates if
`None`. Usually what you want, but a side-effectful default you *intend* to always evaluate
is a subtle bug. Use `.fold(default)(transform)` or precompute the default as a `val`.

### Scala 3 `Null` — opt-in stricter null-safety

Scala 3.0 introduced `-Yexplicit-nulls`. With the flag:

- `Null` becomes a direct subtype of `Any` rather than every reference type. Assigning
  `null` to `String` is a compile error.
- Java return types become *flexible types*: a Java `String` is seen as `String | Null`,
  forcing the call site to handle nullability explicitly.
- Union types replace `Option` at the Java boundary in some codebases.

Opt-in because rewrites at every Java-interop boundary are required. Source:
`docs.scala-lang.org/scala3/reference/other-new-features/explicit-nulls.html`. Contrast with
`kotlin_footguns_expertise.md` §3: Kotlin made null-safety the default with opt-in unsafe
via `!!`; Scala 3 made null-safety opt-in with opt-out unsafe via `null`.

### Audit pattern

- `\.get\b` on `Option`/`Try`/`Either` (high-yield candidate point).
- `Some(` where the inner expression contains a Java method call (compound NPE risk).
- `Await.result(` (§4) — `.get` on a failed Future also throws.
- `null` keyword assignments (legacy interop or explicit unsafety).

---

## 4. `Future` + ExecutionContext, Thread Leaks, No Cancellation

### The primitive

`scala.concurrent.Future[T]` is the standard async monad. Construction requires an implicit
`ExecutionContext`; the most common is `scala.concurrent.ExecutionContext.Implicits.global` —
a fork-join pool sized to `Runtime.availableProcessors`.

### Footgun A: `global` is shared

Every Future on `ExecutionContext.global` runs on the same pool. Spark, Akka, Play, http4s,
and Akka HTTP deliberately do *not* use `global`, but library code importing
`ExecutionContext.Implicits.global` does — producing cross-component scheduling contention.
On a container with cgroup CPU limits (JVM 11+ honors), the pool might be 1-2 threads; a
single blocking Future can hang the whole JVM's `global` EC. Source:
`docs.scala-lang.org/overviews/core/futures.html`,
`beyondthelines.net/computing/scala-future-and-execution-context/`.

### Footgun B: Blocking inside a Future on the same EC

Wrap blocking calls in `scala.concurrent.blocking { ... }` to notify the ForkJoinPool, which
*may* spawn an additional worker. But the Scala Futures documentation explicitly states the `ForkJoinPool` "is not
designed for long-lasting blocking operations. Even when notified with blocking the pool
might not spawn new workers as you would expect." The compound failure: `Await.result` inside
a Future on the same EC — `Future { Await.result(inner, 5.seconds) }`. If `inner` is also on
`global` and the pool has N threads, N outers all blocked waiting for inners that cannot be
scheduled deadlocks the pool. Real production-failure mode. Sources:
`monix.io/docs/current/best-practices/blocking.html`,
`stephenn.com/2018/03/avoiding-scala-thread-exhaustion.html`.

### Footgun C: `Future` does not support cancellation

`scala.concurrent.Future` is non-cancelable by design. Once running, no API interrupts it; the
`Promise` API has no "cancel" path. Long-running Futures no longer needed (client
disconnected, request timed out) keep consuming CPU and resources. **Resource-leak vector**:
an attacker issues many slow requests then disconnects.

The cancellation gap is the biggest design difference between `Future` and modern effect
systems. De Goes cites cancellation as foundational for ZIO: "ZIO… had some of the high-end
features of Haskell's IO monad, including cancellation of running effects." Source:
`degoes.net/articles/zio-history`. Cats Effect `IO.cancelable` and ZIO `ZIO[R, E, A]` treat
cancellation as first-class.

### Footgun D: `Await.result` turns async into sync

`Await.result(future, duration)` blocks the caller. Two compound footguns:

1. Calling from inside an EC consumes a thread (deadlock per Footgun B).
2. `Await.result(future, Duration.Inf)` can hang indefinitely.

Audit pattern: every `Await.result` is a candidate. Default expectation: used *only* at the
application edge (main, HTTP request boundary in a fully-sync framework), never in Future
bodies, library code, or actor behavior.

### Footgun E: Fire-and-forget Future

```scala
Future { somethingExpensive() }  // no .onComplete, .recover, .transform
```

Failures are captured in the Future but never observed. Some EC implementations log
unhandled failures; many do not. Cats Effect `IO` disallows fire-and-forget by construction
(every `IO` must be run or chained). `Future` allows it.

### Cancellation-safe alternatives

- **Cats Effect 3** — `IO[A]` with cancellation, fibers, `Resource[F, A]`, structured
  concurrency (`Supervisor`, `parTraverse`). `typelevel.org/cats-effect/`.
- **ZIO 2** — `ZIO[R, E, A]` with environment, typed errors, fibers, `Scope`-based resources.
  `zio.dev`.
- **Monix 3** — `Task[A]`; largely subsumed by Cats Effect 3.

All three solve cancellation, detect fire-and-forget at compile time (orphaned values warn),
replace `Await.result` with `unsafeRunSync` at the edge. Trade-off: Haskell-influenced
effect-monad style some teams reject for readability.

Cross-link to `race_conditions_concurrency_expertise.md` for the JVM memory model and
happens-before discipline underlying all Scala concurrency.

---

## 5. Pattern Matching Exhaustiveness, Extractors, and `case _`

### The primitive

Scala's `match` is an ADT-analysis construct. For `sealed trait`/`sealed class` with all
subtypes in the same file, the compiler proves exhaustiveness and warns on missing cases.
For unsealed scrutinees (plain trait, `Any`), runtime falls through to `MatchError`.

### The exhaustiveness footgun

Warnings are easy to miss without `-Xfatal-warnings`. Several bug reports document
checker gaps — collection extractors `+:`/`:+` break exhaustiveness
(`users.scala-lang.org/t/does-the-extractor-break-exhaustive-match-checking/6867`), and
generic sealed traits with phantom type parameters produce false-negative warnings
(`github.com/scala/scala3/issues/20132`, `github.com/scala/scala3/issues/20128`).

Anti-pattern:

```scala
sealed trait Permission
case object Read extends Permission
case object Write extends Permission
case object Admin extends Permission

def isAuthorized(p: Permission): Boolean = p match {
  case Read => true
  case Write => requiresElevation
  case _ => false  // catch-all silences the warning
}
```

Adding `case object Delete extends Permission` later does *not* warn. Runtime treats `Delete`
as `false`. In an authorization check, wildcard default-to-deny is probably safe; wildcard
default-to-allow is catastrophic — and the compiler cannot tell which is which.

### `case _` in security-relevant matches

**In permission checks, route dispatches, auth-verification branches, or deserialization
type-tag dispatches, prefer enumerating every case over `case _ =>`.**

### Pattern matching on `Any` / `AnyRef` — runtime type check

Each case compiles to runtime `isInstanceOf[T]`. Generic parameters are erased (§8), so
`List[String]` and `List[Int]` are indistinguishable; compiler warns on `case xs:
List[String]`. The developer can *believe* they type-checked when only the erased type was
checked.

### Guard clauses (`case x if pred(x) =>`)

Guarded cases do not contribute to exhaustiveness analysis — the compiler treats them as
possibly-not-matching. Developer believes "the guards cover the space," but the compiler
cannot verify the predicates.

### Scala 3 `enum` cleanup

```scala
enum Permission { case Read, Write, Admin }
```

Desugars to sealed trait + case-objects with synthesized JVM enum methods. Structural
improvement: language-enforced exhaustiveness bounds, consistent tooling (`enum.values`).
Source: `docs.scala-lang.org/scala3/reference/enums/enums.html`. Footgun lens: `enum` does
NOT eliminate the `case _ =>` anti-pattern; still legal, still silences exhaustiveness.

### Audit pattern

- Grep `case _ =>`, `case _: ` in security-relevant matches.
- Confirm scrutinee is sealed.
- Build with `-Xfatal-warnings -Wunused:patvars -Wnonunit-statement -Wvalue-discard`.

---

## 6. `def` vs `val` vs `lazy val`

### The primitives

- `def x = expr` — method; recomputed on every reference.
- `val x = expr` — field; computed once at init.
- `lazy val x = expr` — field; computed on first access; thread-safe via double-checked
  locking on the enclosing object's monitor.

Identical syntax at use site (`obj.x`); radically different runtime semantics. Switching is
a one-keyword change the compiler accepts silently.

### The "val to def → O(N²)" bug

```scala
class Service { val expensiveCache: Map[Key, Value] = computeExpensiveMap() }
```

Refactoring `val` to `def` makes every reference recompute the map. A loop over a thousand
keys becomes `O(N²)`. Type signature is unchanged. Mirror: `def` to `val` for a side-
effecting method executes the effect once at construction, not per call (silently breaks
"feature flag checked on every request").

### `lazy val` and deadlock

Two `lazy val`s in different objects whose initializers reference each other can deadlock
under concurrent first-access: each thread holds one object's monitor and waits on the
other's. Documented in SIP-20. Scala 3's
`@threadUnsafe` annotation removes synchronization at cost of repeated init
(`docs.scala-lang.org/scala3/reference/changed-features/lazy-vals-init.html`). The
post-Scala-3.3 scheme reduces but does not eliminate the surface. Recursive `lazy val` (init
references itself) is undefined per spec; in practice deadlocks.

### `object` singleton initialization order

`object` declarations are JVM singletons, initialized on first reference. Cross-referencing
`object`s with `val` fields can produce *null fields*: A's init references B, B's init
references A's `val a` which has not yet been assigned, B sees `null`. Documented at
`docs.scala-lang.org/tutorials/FAQ/initialization-order.html`. Mitigation: `lazy val` for
cross-object references.

### Audit pattern

- `val` ↔ `def` refactors in hot paths or side-effecting methods.
- `lazy val` chains across `object`s.
- Cross-referencing `object`-singleton `val` fields.

---

## 7. Case Classes, Equality, `copy`, Serialization

### The primitives

`case class Foo(a: Int, b: String)` auto-generates: constructor, companion `apply`,
structural `equals`/`hashCode`, `toString`, `copy`, `unapply` (for pattern matching).
Scala 2 case classes implement `java.io.Serializable`
and `scala.Product` by default.

### Footgun A: Mutable field in case class

```scala
case class Counter(var n: Int)
val c = Counter(0); val m = Map(c -> "value")
c.n = 1
m.get(c)  // None — the key's hashCode changed
```

Equality is based on field values at comparison time. A `var` field whose value changes after
construction silently invalidates `Set`/`Map` membership. Compiler allows `var` in case
classes without warning.

### Footgun B: Serializable inheritance

Scala 2 `case class` implements `java.io.Serializable` automatically. Every case class is on
the JVM deserialization gadget surface (`java_footguns_expertise.md` §2). Spark uses Java
Serialization by default for closures and broadcast variables; Akka's JavaSerializer
likewise. Akka 2.6+ disables Java serialization by default (opt-in via
`akka.actor.allow-java-serialization = on`) and recommends Jackson. Source: `akka.io/security`,
`doc.akka.io/libraries/akka-core/current/serialization.html`.

Defensive pattern: **never Java-serialize untrusted input**. Use `ObjectInputFilter` (JEP
290, Java 9+) for allowlists. Akka recommends Jackson or Protobuf for cross-node messaging.
Spark's Kryo is an improvement but has its own gadget surface (§10).

### Footgun C: `==` semantics after refactor

Scala's `==` for reference types is `equals(that)`. Case classes have structural equality;
non-case classes fall back to JVM reference equality. Refactoring case class → regular class
(or vice versa) silently changes equality across the codebase. No compiler warning.

### Footgun D: Pickling libraries — uPickle, Circe, Boopickle, Borer

Auto-derived codecs via implicit/given derivation:

- **uPickle** (Lihaoyi) — macro-derived; polymorphic deserialization opt-in.
- **Circe** (Travis Brown) — `circe-generic` derives via shapeless (Scala 2) or `Mirror`
  (Scala 3); polymorphic deserialization requires explicit `Discriminator`.
- **Boopickle** — binary; macro-derived; symmetric-trust use case.
- **Borer** — CBOR/JSON; type-class-based; explicit type-tag handling.

Cross-cutting footgun: type-class derivation makes it ergonomic to expose a serialization
surface without an explicit permitted-type allowlist. `derives Codec` on a sealed trait
exposes every subtype's constructor params; later adding a subtype with a `Throwable` field
silently widens the gadget surface. Audit: enumerate every `derives` / `implicit val codec`
and verify the type allowlist.

Cross-link to `java_footguns_expertise.md` §2 (Java Serialization) and
`deserialization_expertise.md` for the cross-language gadget catalog.

---

## 8. Variance, Type Erasure, Type-System Escape Hatches

### The primitives

- `class Box[T]` — invariant. Default.
- `class Producer[+T]` — covariant. Output positions only.
- `class Consumer[-T]` — contravariant. Input positions only.

Variance is compiler-checked: a covariant `T` in an input position is a compile error
("covariant type T occurs in contravariant position"). Real type-safety win.

### Footgun A: Mutable covariant field — compile error / `private[this]` escape

`class Box[+T](var x: T)` is rejected. The workaround `class Box[+T](private[this] var x: T)`
compiles by reducing visibility to instance scope, but loses the guarantee — the mutable
field can still cause `ClassCastException` if the box is cast to a more-specific type.

### Footgun B: `asInstanceOf[T]` is an unchecked runtime cast

The compiler does not verify; runtime `checkcast` throws on mismatch (modulo erasure).
Every `.asInstanceOf[T]` is a "trust me" assertion. Unsafe:

```scala
val xs: List[Any] = receiveJsonList()
xs.map(_.asInstanceOf[String])
```

The cast throws at the consuming site, not the parsing site. Cross-link to
`code_review_expertise.md` §3 — `asInstanceOf` is a high-yield audit point.

### Footgun C: Type erasure

`List[String]` and `List[Int]` are both `scala.collection.immutable.List` at bytecode level.
Consequences: `case xs: List[String]` only checks `xs` is a List (compiler warns on
unchecked pattern); reflection on `Class[List[String]]` returns the erased type;
`manifest[T]` / `TypeTag[T]` / Scala 3 `Type[T]` quotes require explicit threading. Type
erasure interacts with polymorphic deserialization identically to Java: the deserializer
needs a discriminator field, type tag, or registration — each is an attack surface without
an allowlist.

### Footgun D: F-bounded polymorphism

`trait Comparable[T <: Comparable[T]]` (CRTP).
Type signatures are difficult to debug; constraint propagates through every function. In
security-relevant code, type-class encoding (`Comparable[T]` as implicit/given) is clearer.

### Footgun E: Scala 3 type-class derivation + Mirrors

```scala
case class User(name: String) derives Codec
```

Invokes `Codec.derived(using Mirror.ProductOf[User])`. Looks declarative but is compile-time
codegen running library-author macros. A `Codec.derived` macro can produce *any* code —
accept polymorphic input, register the type globally. Every `derives` clause should be
cross-referenced with library docs.

Cross-link to `kotlin_footguns_expertise.md` for the contrasting use-site variance approach
(`out`/`in`).

---

## 9. Akka / Pekko — Actor Model

### The primitives

`ActorSystem` runtime, `Actor` / `Behavior` (Akka Typed), `ActorRef[T]`, dispatchers
(per-system thread pools), routing, supervision, clustering, persistence, Akka Streams, Akka
HTTP — all built on actor primitives.

Lightbend changed Akka's license from Apache 2.0 to BUSL 1.1 in 2022; **Apache Pekko** is
the ASF-maintained Apache-License fork of Akka 2.6 for projects that cannot accept BUSL.
Sources: `pekko.apache.org`, `blog.lunatech.com/posts/2023-10-27-akka-licence-change-one-year-later`.
Pekko's API is near-identical; security surface applies to both.

### Footgun A: `tell` is fire-and-forget

`ref ! message` sends to the mailbox, returns `Unit`. No ack, no error path (dead-lettered if
actor missing). Developers who want a reply use `?` (ask) → `Future[Any]` plus an implicit
`Timeout`. The `?` inherits all Future footguns from §4.

### Footgun B: Unbounded mailbox by default

Default `UnboundedMailbox` (backed by `ConcurrentLinkedQueue`) has no message limit. Akka
documentation explicitly: "in a scenario where messages are added to the mailbox faster than
the actor can process them, this can lead to the application running out of memory." Source:
`doc.akka.io/libraries/akka-core/current/mailboxes.html`.

**DoS vector**: an attacker flooding an actor (directly via Akka Remoting, or via HTTP →
actor message translation) exhausts JVM heap. Mitigation: `BoundedMailbox` with explicit
capacity — opt-in, per-actor.

### Footgun C: `become` / `unbecome` ordering

Akka Classic's `context.become(newBehavior)` applies to *subsequent* messages.
Already-mailboxed messages at the time of `become` are processed by the *new* behavior, not
the old. Akka Typed replaces this with returning a new `Behavior[T]`, structurally clearer.

### Footgun D: `stash` / `unstash` discipline

Forgetting `unstashAll`, calling it twice, or stash overflow (capacity limit) — Akka throws
`StashOverflowException` on overflow.

### Footgun E: Cluster state propagation

Akka Cluster propagates membership via gossip; node-joins are eventually consistent
(milliseconds to seconds). Code assuming immediate consistency races. `ClusterSingleton`,
`ClusterSharding`, `ClusterClient` abstract the timing but eventual-consistency is permanent.
Cross-link to `race_conditions_concurrency_expertise.md`.

### Footgun F: Akka HTTP routing DSL — order matters

```scala
val route = pathPrefix("api") {
  path("public") { complete("public") } ~
  authenticateBasic("realm", auth) { user =>
    path("private") { complete(s"hello $user") }
  } ~
  path("admin") { complete("admin") }  // FOOTGUN: outside the authenticate block
}
```

First matching route wins. A `path("admin")` outside the `authenticateBasic` block is an
unauthenticated admin endpoint. Compiler does not warn. Audit: enumerate every `path(...)` /
`pathPrefix(...)` and trace authentication nesting. Source:
`doc.akka.io/libraries/akka-http/current/routing-dsl/style-guide.html`.

Cross-link to `java_footguns_expertise.md` §2 (Akka's pre-2.6 default Java serialization is
the canonical Akka security advisory) and `distributed_authz_expertise.md`.

---

## 10. Spark / Functional-Pipeline Footguns

### The primitives

`RDD[T]` (lazy transformations), `DataFrame` / `Dataset[T]` (schema-aware tabular),
`SparkSession`, UDFs (user-defined functions registered in Spark SQL).

### Footgun A: RDD closure serialization

`rdd.map(fn)` serializes `fn` and ships it to workers. A method on a class captures the
*entire* enclosing class; non-`Serializable` enclosing class → `org.apache.spark.SparkException:
Task not serializable`. Source:
`mallikarjuna_g.gitbooks.io/spark/content/spark-tips-and-tricks-sparkexception-task-not-serializable.html`.

Mitigations: declare enclosing class `Serializable`; capture as local `val` before use;
broadcast variables for large read-only state; `@transient lazy val` for non-serializable
fields.

Security footgun: **whatever the closure captures, Spark serializes and ships to workers**.
Accidentally-captured auth tokens, database connections, private keys are serialized and sent
to every worker. In mixed-trust clusters, the closure boundary is a real exfiltration vector.

### Footgun B: DataFrame schema inference

`spark.read.json(path)` infers schema from a sample (best-effort). A field appearing as `123`
and `"123"` is inferred as `String`. A field appearing in some records becomes
`nullable: true`. Schema drift across input files produces silently-different behavior
across runs. Audit: explicit `spark.read.schema(StructType(...))` for production pipelines.

### Footgun C: Spark SQL UDF null handling

A UDF `Int => Int` NPEs on `null` input — Scala's `Int` extends `AnyVal` and cannot hold
null, but Spark's column is `java.lang.Integer` which can. Use `java.lang.Integer` (boxed,
nullable) or `expr.isNotNull` before invoking.

### Footgun D: Catalyst optimizer side-effect ordering

Catalyst reorders / rewrites query plans. A UDF with observable side effects (database
writes, external API calls) can execute zero times (pruned), once, or many times.
`fn.asNondeterministic()` partially mitigates but does not prevent cross-stage reorder.

Cross-link to `java_footguns_expertise.md` §2 — Spark closure serialization defaults to Java
Serialization. Kryo is opt-in. CVE-2022-36944 (`LazyList` `Function0` chain, scala-library
2.13.0–2.13.8) is a Java-deserialization gadget in the Scala standard library itself — see Snyk record.

---

## 11. sbt and Supply Chain

### The primitives

`build.sbt` is a Scala DSL compiled and run as Scala code at sbt startup. Plugins
(`project/plugins.sbt` with `addSbtPlugin(...)`) are downloaded from Maven, added to the
build classpath, and execute arbitrary code at init. **Coursier** (`coursier.io`) is the
de-facto resolver. Artifacts publish to Maven Central via the Sonatype Central Publisher Portal (OSSRH reached end of life June 30, 2025).

### Footgun A: `build.sbt` is arbitrary Scala

Not declarative configuration. Any expression can do network calls, file-system reads,
`Process(...).!!`, env reads. Developers skim `build.sbt` for "obvious" malicious patterns
rather than reviewing as application code.

### Footgun B: CVE-2026-32948 — sbt source-dependency command injection (Windows)

`ProjectRef(uri, project)` and `RootProject(uri)` take a VCS URI. On Windows, sbt invokes the
VCS via `Process("cmd", "/c", ...)`. The URI fragment is user-controlled and passed to
`cmd /c` without escaping; `&`/`|`/`;` are interpreted as separators. Fixed in sbt 1.12.8 and
2.0.0-RC10. Sources:
`advisories.gitlab.com/pkg/maven/org.scala-sbt/sbt/CVE-2026-32948/`,
`scala-lang.org/blog/2026/03/31/sbt-security-advisory.html`.

Footgun lens: URI fragments derived from branch names or env vars are user-influenced data.
Allowlist-validate the fragment before passing to a shell.

### Footgun C: sbt plugins — arbitrary code via project compile

A plugin downloaded from Maven runs its init code at sbt startup with full filesystem/network
access. Malicious plugins can exfiltrate env vars, modify the build classpath, or publish
artifacts. The org-wide cooldown policy (`min-release-age`) applies via Renovate / Dependabot
PR-bot policy. Cross-link to `cicd_supply_chain_expertise.md` §5.

### Footgun D: Cross-build matrix sprawl

`crossScalaVersions := Seq("2.12.18", "2.13.12", "3.3.1")` — each
`(library × scalaVersion × platform)` cell is a separately-published artifact with its own
signing chain. A compromised signing key can publish a malicious artifact for one version
while leaving others legitimate; cross-version inconsistency goes unnoticed.

Cross-link to `java_footguns_expertise.md` §11 (Maven supply chain shared) and
`cicd_supply_chain_expertise.md`.

---

## 12. Cats Effect, ZIO, Effect-System Footguns

### The primitives

Effect systems encode side effects as values of type `F[A]`:

- **Cats Effect 3** — `IO[A]`, `Resource[F, A]`, `Fiber[F, E, A]`, `Supervisor`, integrated
  with the `cats` type-class hierarchy.
- **ZIO 2** — `ZIO[R, E, A]` (environment, typed errors, success), `Scope`, `Fiber[E, A]`,
  `ZLayer` for DI.

Both are referentially transparent: an `IO[A]` is a *description* of an effect, not the
effect. To run, call `unsafeRunSync` (Cats Effect) or hand to a runtime (ZIO).

### Footgun A: `unsafeRunSync` breaks referential transparency

Sprinkling `unsafeRunSync` throughout the codebase produces three problems:

1. **Cancellation gaps** — the resulting Future is not Cats-Effect-cancelable.
2. **Resource lifecycle skipped** — `Resource` cleanup ties to IO evaluation; discarded
   results may not release.
3. **Composition broken** — `unsafeRunSync` is a one-way boundary.

Audit: every `unsafeRun*` is a candidate. Default expectation: application edge only (`main`,
HTTP request boundary, Akka receive handler bridging to IO).

### Footgun B: `Resource` discipline

```scala
Resource.make(IO(openFile()))(f => IO(f.close())).use { f =>
  IO(processFile(f))
}
```

`.allocated` returns `(A, IO[Unit])` — developer must run the release manually. Most don't;
resource leaks until JVM shutdown. Audit: `Resource.allocated` outside test harnesses is a
code smell.

### Footgun C: Dispatcher / EC mismatch in Cats Effect

The CE3 runtime has compute (CPU-bound), blocking (I/O), and scheduler pools. Forgetting
`IO.blocking` for I/O on the compute pool exhausts compute threads under load: filesystem
I/O on compute pool → CPU-bound work backs up → latency spikes → `IOTimeoutException`s on
otherwise-fast effects.

### Footgun D: ZIO environment threading

`R` is structurally `DatabaseService & HttpClient` (ZIO 2 removed `Has`). Missing dependency is a
compile error (good) with opaque messages. *Misconfigured* `ZLayer` (production impl in test
context) produces silent incorrect behavior.

Cross-link to `java_footguns_expertise.md` §6 and
`race_conditions_concurrency_expertise.md` — JMM applies to all Scala concurrency primitives.

---

## 13. Detection Patterns and Linters

### Semgrep patterns

Cross-link to `semgrep_rule_authoring.md`. High-yield Scala-specific patterns:

- `$X.get` where `$X: Option[...] | Try[...] | Either[..., ...]`.
- `Await.result(...)` / `Await.ready(...)` outside application-edge context.
- `import scala.concurrent.ExecutionContext.Implicits.global` in library code.
- `implicit def $X($Y: $S): $T` definitions — cross-reference safe-conversion allowlist.
- `case _ =>` in security-relevant `match` expressions (auth, permission, route scrutinees).
- `asInstanceOf[$T]` — all sites manual review.
- `ObjectInputStream` instantiation — high-severity deserialization sink.
- Akka `JavaSerializer` usage or `akka.actor.serialization` configuration.
- `Future { ... }` without `.recover`/`.onComplete`/`.transform` — best-effort orphan
  detection.
- `unsafeRun*` calls outside application edge.

### Scapegoat (compiler plugin)

`github.com/scapegoat-scala/scapegoat`. ~120 inspections; opt-in via sbt plugin. Notable:
`OptionGet`, `AsInstanceOf`, `CatchThrowable`, `NullParameter`, `EmptyCaseClass`,
`MaxParameters`, `RedundantFinalModifierOnMethod`.

### WartRemover (compiler plugin)

`wartremover.org`. FP-correctness focused. Notable warts: `Any`, `AsInstanceOf`,
`DefaultArguments`, `ImplicitConversion`, `IsInstanceOf`, `NonUnitStatements`, `Null`,
`OptionPartial`, `Throw`, `TryPartial`, `Var`. Source:
`wartremover.org/doc/install-setup.html`.

### Scalafix

`scalacenter.github.io/scalafix/`. Refactoring + audit; most active development of the
three. Security-relevant rules: `DisableSyntax` (configurable blocklist of `null`, `var`,
`Await.result`, etc.), `RedundantSyntax`.

### JVM ecosystem tooling

Scala artifacts are Maven artifacts; Snyk, Sonatype Nexus Lifecycle, GitHub Dependabot,
Renovate all cover Scala via Maven coordinates. CVE coverage identical to Java. Cross-link
to `cicd_supply_chain_expertise.md` §3.

### Compiler flags as detection

With `-Xfatal-warnings`, these become errors: `-Wunused:imports`, `-Wunused:locals`,
`-Wunused:patvars`, `-Wnonunit-statement`, `-Wvalue-discard`, `-Xlint:adapted-args`,
`-Xlint:nullary-unit`. Enabling all is the standard "strict mode." Source:
`docs.scala-lang.org/overviews/compiler-options/index.html`.

---

## 14. Defensive Checklist and Variant Analysis

### Twelve-item defensive checklist

For any Scala codebase touching untrusted input or security-sensitive flow:

1. **Run `-Xfatal-warnings` plus the strict lint suite** (`-Wunused:imports`,
   `-Wunused:locals`, `-Wunused:patvars`, `-Wnonunit-statement`, `-Wvalue-discard`,
   `-Xlint:_`). Catches most exhaustiveness, value-discard, and unused-binding bugs.
2. **Add Scapegoat + WartRemover (or Scalafix) to CI.** Configure to ban `Option.get`,
   `asInstanceOf`, `null`, `var` (where feasible), `Await.result` (in library code),
   `Throw`, and implicit conversion definitions.
3. **Never use Java Serialization on untrusted input.** Configure Akka serialization to use
   Jackson or Protobuf; configure Spark to use Kryo with a registered class list; never feed
   `ObjectInputStream` from network or file input without `ObjectInputFilter`.
4. **Audit every `match` expression in security-relevant code** for `case _ =>` catch-alls.
   Confirm the scrutinee type is sealed; consider replacing the catch-all with explicit cases.
5. **Audit every `Option.get` / `Try.get` / `Either.right.get`** for runtime exception risk.
   Prefer `getOrElse(default)`, `.fold(default)(transform)`, or pattern matching.
6. **Audit every Java-interop boundary for `null` handling.** Wrap returns in `Option(...)`
   not `Some(...)`. Consider enabling Scala 3 `-Yexplicit-nulls` (opt-in).
7. **Audit `ExecutionContext` choice.** Library code should *not* import
   `ExecutionContext.Implicits.global`; require the EC to be passed in. Wrap blocking calls
   in `scala.concurrent.blocking { ... }`. Avoid `Await.result` outside the application
   edge.
8. **Audit Akka actor mailboxes.** Configure bounded mailboxes for actors that handle
   untrusted input (HTTP request handlers, WebSocket consumers, network ingestion).
9. **Audit `case class` Serializable mixins.** Identify which case classes are reachable
   from a deserialization sink and verify the deserializer uses an allowlist.
10. **Audit `implicit` / `given` definitions for action-at-a-distance.** Map the import
    surface of each file and verify the implicit-resolution outcome at every call site.
11. **Audit sbt plugin list (`project/plugins.sbt`)** with the same rigor as application
    dependencies. Pin plugin versions to specific releases. Apply a minimum-release-age
    policy via Renovate / Dependabot. Review plugin source on first introduction.
12. **Treat `build.sbt` as code.** Apply the same review standard as application code; no
    `sys.env(...)`-driven `Process` calls without explicit allowlist validation.

### Variant analysis

#### Scala.js — different runtime

`scala-js.org` compiles Scala to JavaScript. JVM-specific footguns mostly do not apply
(`null` is JS `null`; no `Serializable`; no JMM). JavaScript-runtime footguns apply instead:
prototype pollution (cross-link to `javascript_node_footguns_expertise.md`), event-loop
blocking, npm supply chain. Implicit-resolution footguns DO still apply at compile time.

#### Scala 3 type-system changes

Intersection types, union types, opaque types, match types, inline methods. Match types
(`type Foo[T] = T match { case Int => String; ... }`) change resolution at a distance like
implicits. Opaque types provide stronger encapsulation than Scala 2's "value class via
implicit." Source: `docs.scala-lang.org/scala3/reference/new-types/index.html`. Security
research coverage emerging.

#### Dotty experimental features

`import scala.language.experimental.<feature>` (modularity, macros 2, capture checking,
named tuples, dependent types) should not appear in production code; flag for re-design.

#### Scala Native — different memory model

`scala-native.org` compiles to LLVM IR with custom GC (Boehm / Immix), no JVM, no
`java.lang.*`. JVM-shared footguns mostly do not apply. New footguns: manual memory via
`Zone`/`Ptr`, C interop (`extern`, `CFuncPtr`), stack overflows. Cross-link to
`c_cpp_footguns_expertise.md` and `firmware_embedded_security.md`.

### Cross-link summary

JVM family: `java_footguns_expertise.md` (parent), `kotlin_footguns_expertise.md` (sibling).
Cross-language: `deserialization_expertise.md` (gadget chains),
`race_conditions_concurrency_expertise.md` (memory model),
`cicd_supply_chain_expertise.md` (Maven/sbt supply chain).

---

## 15. References

### Scala language and platform

- Scala Language reference: `docs.scala-lang.org/`,
  `docs.scala-lang.org/scala3/reference/contextual/`,
  `docs.scala-lang.org/scala3/reference/changed-features/lazy-vals-init.html`,
  `docs.scala-lang.org/scala3/reference/experimental/explicit-nulls.html`
- Scala Improvement Process (SIP) index: `docs.scala-lang.org/sips/`,
  `scalajp.github.io/scala.github.com/sips/pending/improved-lazy-val-initialization.html`
- Scala Best Practices (Nicolas Rinaudo): `nrinaudo.github.io/scala-best-practices/`,
  `nrinaudo.github.io/scala-best-practices/partial_functions/option_get.html`
- alexandru/scala-best-practices: `github.com/alexandru/scala-best-practices/blob/master/sections/4-concurrency-parallelism.md`
- Scala API documentation: `scala-lang.org/api/2.13.6/scala/Option.html`,
  `scala-lang.org/api/2.13.3/scala/concurrent/ExecutionContext.html`,
  `scala-lang.org/api/2.13.6/scala/concurrent/Future.html`
- Scala compiler options: `docs.scala-lang.org/overviews/compiler-options/index.html`

### Implicits / contextual abstractions

- Implicit Conversions: `docs.scala-lang.org/tour/implicit-conversions.html`,
  `docs.scala-lang.org/scala3/book/ca-implicit-conversions.html`
- Implicit Classes (SIP-13): `docs.scala-lang.org/sips/implicit-classes.html`
- Scala 3 Contextual Abstractions:
  `docs.scala-lang.org/scala3/reference/contextual/`,
  `docs.scala-lang.org/scala3/reference/contextual/relationship-implicits.html`
- Scala 3 Migration Guide (Contextual):
  `docs.scala-lang.org/scala3/guides/migration/incompat-contextual-abstractions.html`

### Future / ExecutionContext / Effect Systems

- Futures and Promises: `docs.scala-lang.org/overviews/core/futures.html`
- Cats Effect: `typelevel.org/cats-effect/`,
  `typelevel.org/cats-effect/docs/2.x/datatypes/io`,
  `typelevel.org/cats-effect/api/3.x/cats/effect/IO.html`,
  `typelevel.org/blog/2017/05/02/io-monad-for-cats.html`
- ZIO: `zio.dev`, `degoes.net/articles/zio-history`, `github.com/jdegoes`
- Monix: `monix.io`, `monix.io/docs/current/best-practices/blocking.html`
- "Calling Blocking Code: There Is No Free Lunch" (Colin Breck):
  `blog.colinbreck.com/calling-blocking-code-there-is-no-free-lunch/`
- "Avoiding Scala Thread Exhaustion in Scalacache":
  `stephenn.com/2018/03/avoiding-scala-thread-exhaustion.html`
- "Understanding Scala Futures and Execution Contexts":
  `beyondthelines.net/computing/scala-future-and-execution-context/`
- Nested Futures parallelism issue: `github.com/scala/bug/issues/12089`

### Akka / Pekko

- Akka Documentation: `doc.akka.io/`, `akka.io/`
- Akka Mailboxes: `doc.akka.io/libraries/akka-core/current/mailboxes.html`,
  `doc.akka.io/libraries/akka-core/current/typed/mailboxes.html`,
  `getakka.net/articles/actors/mailboxes.html`
- Akka HTTP Routing DSL: `doc.akka.io/libraries/akka-http/current/routing-dsl/index.html`,
  `doc.akka.io/docs/akka-http/current/routing-dsl/style-guide.html`
- Akka licence change: `blog.lunatech.com/posts/2023-10-27-akka-licence-change-one-year-later`,
  `akka.io/security`
- Apache Pekko: `pekko.apache.org/`, `github.com/apache/pekko`,
  `issues.apache.org/jira/browse/LEGAL-714`,
  `cwiki.apache.org/confluence/display/INCUBATOR/PekkoProposal`
- Akka actor source (Mailbox.scala):
  `github.com/akka/akka/blob/main/akka-actor/src/main/scala/akka/dispatch/Mailbox.scala`
- *Effective Akka* (Jamie Allen, 2013):
  `oreilly.com/library/view/effective-akka/9781449360061/`

### Pattern matching and types

- Pattern Matching: `docs.scala-lang.org/tour/pattern-matching.html`
- Sealed Keyword: `baeldung.com/scala/sealed-keyword`
- Scala 3 Enums: `docs.scala-lang.org/scala3/reference/enums/enums.html`
- Variances: `docs.scala-lang.org/tour/variances.html`,
  `docs.scala-lang.org/scala3/book/types-variance.html`
- Exhaustiveness check issues: `github.com/scala/scala3/issues/20132`,
  `github.com/scala/scala3/issues/20128`,
  `github.com/scala/bug/issues/8511`,
  `users.scala-lang.org/t/does-the-extractor-break-exhaustive-match-checking/6867`

### Null / Option discipline

- Scala 3 Explicit Nulls SIP review:
  `contributors.scala-lang.org/t/sip-public-review-explicit-nulls/3889`
- Initialization order FAQ:
  `docs.scala-lang.org/tutorials/FAQ/initialization-order.html`
- "Misuse of Option and Null in Scala":
  `softwarepatternslexicon.com/scala/anti-patterns-in-scala/misuse-of-option-and-null/`

### Lazy vals and concurrency

- SIP-20 lazy-val improvements:
  `scalajp.github.io/scala.github.com/sips/pending/improved-lazy-val-initialization.html`
- @threadUnsafe annotation: `baeldung.com/scala/scala-3-threadunsafe`
- Lazy vals init (Scala 3):
  `docs.scala-lang.org/scala3/reference/changed-features/lazy-vals-init.html`
- "On the Future of Lazy Vals In Scala" (Aleksandar Prokopec):
  `aleksandar-prokopec.com/2013/06/10/on-lazy-vals.html`
- Lazy-val deadlock bug: `github.com/scala/scala3/issues/21298`

### Spark

- Apache Spark documentation: `spark.apache.org/docs/latest/`
- "Spark Task not serializable" troubleshooting:
  `mallikarjuna_g.gitbooks.io/spark/content/spark-tips-and-tricks-sparkexception-task-not-serializable.html`,
  `databricks.gitbooks.io/databricks-spark-knowledge-base/content/troubleshooting/javaionotserializableexception.html`,
  `dorianbg.github.io/posts/how-to-fix-task-not-serializable-issues-in-apache-spark/`
- "Serialization in Spark": `lifeisafile.com/Serialization-in-spark/`

### sbt and supply chain

- sbt Documentation: `scala-sbt.org/1.x/docs/`
- sbt Plugins: `scala-sbt.org/1.x/docs/Plugins.html`,
  `scala-sbt.org/1.x/docs/Using-Plugins.html`,
  `scala-sbt.org/1.x/docs/Plugins-Best-Practices.html`
- sbt build definition: `scala-sbt.org/1.x/docs/Basic-Def.html`
- CVE-2026-32948 sbt source-dependency command injection (Windows):
  `advisories.gitlab.com/pkg/maven/org.scala-sbt/sbt/CVE-2026-32948/`,
  `scala-lang.org/blog/2026/03/31/sbt-security-advisory.html`
- Coursier: `get-coursier.io/`

### Vulnerability records / CVE database

- Snyk Scala vulnerabilities database:
  `security.snyk.io/package/maven/org.scala-lang%3Ascala-library`,
  `snyk.io/vuln/maven:com.fasterxml.jackson.module:jackson-module-scala`,
  `security.snyk.io/package/maven/com.fasterxml.jackson.module%3Ajackson-module-scala`
- CVE-2022-36944 LazyList Function0 deserialization RCE:
  `security.snyk.io/vuln/SNYK-JAVA-ORGSCALALANG-3032987`,
  `security.snyk.io/vuln/SNYK-RHEL8-SCALA-5530115`
- Jackson Deserialization Vulnerability writeup (Snyk):
  `snyk.io/blog/jackson-deserialization-vulnerability/`
- SecureFlag Scala Unsafe Deserialization:
  `knowledge-base.secureflag.com/vulnerabilities/unsafe_deserialization/unsafe_deserialization_scala.html`
- Kodem Scala vulnerability best practices:
  `kodemsecurity.com/resources/tips-to-reduce-scala-vulnerabilities`

### Static analysis tooling

- Scapegoat: `github.com/scapegoat-scala/scapegoat`,
  `github.com/scapegoat-scala/scapegoat/blob/master/README.md`
- WartRemover: `wartremover.org/`, `wartremover.org/doc/install-setup.html`
- Scalafix: `scalacenter.github.io/scalafix/`,
  `scalacenter.github.io/scalafix/docs/users/related-projects.html`
- Linter (HairyFotr): `github.com/HairyFotr/linter`
- "Scala lint tools" comparison: `alvinalexander.com/misc/scala-lint-tools-rules-code-checker-scalastyle-wartremover/`
- Codacy Scala review: `blog.codacy.com/review-of-scala-static-analysis-tools`
- "Tools to guide code quality" (Underscore):
  `underscore.io/blog/posts/2014/08/28/tools-to-guide-code-quality.html`

### Researcher pages

- Martin Odersky: `people.epfl.ch/martin.odersky`,
  `2025.workshop.scala-lang.org/profile/martinodersky`
- Adriaan Moors: `adriaanm.github.io/`, `github.com/adriaanm`,
  `chariotsolutions.com/podcast/techcast-98-adriaan-moors-scala/`
- Lukas Rytz: `lrytz.github.io/`, `github.com/lrytz`
- Sébastien Doeraene: `lampwww.epfl.ch/~doeraene/`,
  `lampwww.epfl.ch/~doeraene/thesis/`, `github.com/sjrd`
- Travis Brown: `github.com/travisbrown`,
  `meta.plasm.us/posts/2021/11/17/scala-open-source/`
- John A. De Goes: `github.com/jdegoes`, `degoes.net/`,
  `ziverge.com/post/zio-in-2025`

### Cross-language deserialization

For non-Scala deserialization (Java `ObjectInputStream`, Python pickle, .NET BinaryFormatter,
Ruby Marshal, PHP unserialize, ML pickle), the canonical home is
`deserialization_expertise.md`. This Scala footgun doc focuses on Scala-language-internal
primitive defaults plus the Scala-specific layers atop Java's serialization tradition.

### Tooling at the boundary

- OWASP Dependency-Check (Maven coverage for Scala): `owasp.org/www-project-dependency-check/`
- GitHub Security Lab CodeQL Scala / Java queries:
  `github.com/github/codeql/tree/main/java/ql/src/Security`
- Trail of Bits publications: `github.com/trailofbits/publications`,
  `blog.trailofbits.com/categories/audits/`

---

## End notes

This doc occupies the Scala slot in the language-specific behavioral-footgun class. The
guiding lens is "primitives unsafe by default." JVM-shared surface is owned by
`java_footguns_expertise.md`; this covers Scala-specific primitives (implicits, Option,
Future / EC, pattern matching, lazy vals, case-class equality, variance, Akka, Spark, sbt,
Cats Effect / ZIO) and the Scala-on-JVM seams.

Three recurring patterns: (1) Scala features designed to *fix* Java footguns (Option fixes
null; pattern matching fixes instanceof; Future fixes manual thread management) leave the
unsafe Java primitive available; (2) the Scala feature itself introduced new footguns
(`Option.get`, `case _`, `Future.global`) mirroring the old; (3) Scala 3 structural
improvements (given/using, explicit nulls, enum) are usually opt-in and most codebases do
not opt in. Audit pattern: map the seams; check the opt-in flags.

Kotlin is the next JVM-sibling deepening (`kotlin_footguns_expertise.md`), authored in
parallel with this shift.
