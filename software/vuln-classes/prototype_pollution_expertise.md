# Prototype Pollution — Primitives, Gadgets, and Defenses
## Synthesized from Olivier Arteau, Mikhail Shcherbakov, Sebastian Lekies, Michał Bentkowski, BlackFan (Sergey Bobrov), Posix, s1r1us, Gareth Heyes, the Snyk research team, and Kurt Boberg

> **Researchers:**
> - **Olivier Arteau** — Formalized the class in 2018. NorthSec 2018 talk "Prototype pollution attacks in NodeJS applications" is the canonical reference; its "vulnerable patterns" enumeration (recursive merge, deep clone with key recursion, object-path setters) is still the working taxonomy. Reported CVE-2018-3721 in lodash — the disclosure that catalyzed an ecosystem-wide audit.
> - **Mikhail Shcherbakov** — KTH Royal Institute of Technology (with Musard Balliu and Cristian-Alexandru Staicu). First author of "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" (USENIX Security 2023) and co-author of "GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes" (USENIX Security 2024). The work that moved server-side pollution from "DoS curiosity" to "RCE-grade vulnerability class": 11 universal gadgets in core Node.js APIs and 56 more via V8-instrumented dynamic taint analysis. Maintains KTH-LangSec/server-side-prototype-pollution and KTH-LangSec/silent-spring.
> - **Sebastian Lekies** — Google researcher; co-author of "Code-Reuse Attacks for the Web: Breaking Cross-Site Scripting Mitigations via Script Gadgets" (CCS 2017, with Kotowicz, Groß, Vela Nava, Johns). Script-gadget research is the structural foundation for client-side pollution-to-XSS chains: even when raw script injection is blocked by CSP, a polluted property can reach a code-eval primitive in legitimate library code.
> - **Michał Bentkowski (@SecurityMB), Securitum** — Author of "Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)," demonstrating that a single Timelion pollution combined with a NODE_OPTIONS / child_process gadget yielded full RCE against Elastic's dashboard. Also "Prototype pollution – and bypassing client-side HTML sanitizers" — the canonical reference for using `__proto__` mutations to defeat DOMPurify-class allowlists.
> - **BlackFan (Sergey Bobrov)** — Maintains github.com/BlackFan/client-side-prototype-pollution, the largest curated corpus of client-side gadgets: per-library writeups for jQuery, Google Closure, js-xss, Embedly, Popper.js, Twitter UWT, Adobe Dynamic Tag Management, and others (29 libraries in all). Also BlackFan/cspp-tools, which includes a prototype_checker script.
> - **Posix** — Pseudonymous researcher responsible for RCE-via-template-engine gadgets in Handlebars and Pug ("AST Injection").
> - **s1r1us (@S1r1u5_)** — Bug-bounty researcher; co-presented "ElectroVolt: Pwning Popular Desktop apps while uncovering new attack surface on Electron" (Black Hat USA 2022); 4th place PortSwigger Top 10 Web Hacking Techniques 2021 for "Exploiting Client-Side Prototype Pollution in the wild". HackerOne writeups are the working catalogue of how the bug class manifests in production bounty programs.
> - **Gareth Heyes (@garethheyes), PortSwigger Research** — "Server-side prototype pollution: Black-box detection without the DoS" (NullCon Berlin / OWASP Global AppSec Dublin 2023). Solved black-box detection: prior techniques required pollution that caused server crashes; Heyes' uses harmless type-confusion properties (`__proto__[status]=510`) yielding observable, non-destructive response deltas. Implemented as an open-source Burp Suite extension.
> - **Snyk research team** — Ecosystem-wide disclosures including CVE-2019-10744 (lodash). security.snyk.io is the de-facto canonical CWE-1321 catalogue.
> - **Kurt Boberg (@lapt0r / GHSA reporter `kurt-r2c`)** — Staff Security Researcher at Semgrep. Three publicly-credited prototype pollution CVEs: **CVE-2021-3805** (object-path `del()` pollution; GHSA-8v63-cqqc-6r2c); **CVE-2020-28472** (`@aws-sdk/shared-ini-file-loader` pollution via crafted INI; GHSA-rrc9-gqf8-8rwg); **CVE-2019-5428** (jQuery `$.extend(true, ...)` pollution across npm, NuGet, RubyGems `jquery-rails` and Maven packages; advisory withdrawn as a duplicate of CVE-2019-11358; GHSA-wv67-q8rr-grjp).
>
> Sources: NorthSec 2018 video; USENIX Security 2023/2024 papers; arXiv 2207.11171, 2407.10812; research.securitum.com; portswigger.net/research; github.com/BlackFan; github.com/KTH-LangSec; snyk.io/blog; security.snyk.io; nvd.nist.gov; github.com/advisories; blog.s1r1us.ninja; cheatsheetseries.owasp.org; MITRE CWE-1321.

---

## 1. The Primitive — Why JavaScript Is Uniquely Vulnerable

### Object.prototype is a global shared parent

Every plain JavaScript object — every `{}`, every `JSON.parse(...)` result, every literal created by deserialization, every parser output — inherits from `Object.prototype` by default. The chain is dynamic: a property assigned to `Object.prototype` at any point during the process lifetime becomes immediately readable through *every* plain object, including objects created before the assignment.

This is the structural fact that makes prototype pollution a vulnerability *class* rather than a single-library bug. Every other major runtime has some notion of namespace isolation between trusted runtime code and user-controlled data structures (JVM ClassLoaders, CLR AppDomains, etc.). JavaScript does not: `Object.prototype` is simultaneously the parent of every untrusted JSON document the application has parsed AND the parent of every runtime helper object the application uses for control-flow decisions. There is no "untrusted Object.prototype" and "trusted Object.prototype." There is only one.

### Three reachability paths to Object.prototype

A user-controlled string can reach `Object.prototype` through three distinct property names:

1. **`__proto__`** — A getter/setter pair defined on `Object.prototype` itself that, when accessed on an instance, reads or writes the instance's internal `[[Prototype]]` slot. Assignment to `obj.__proto__.x = 1` walks up to `Object.prototype` and assigns `x` there. Disabled by Node.js's `--disable-proto=delete` or `--disable-proto=throw` flag (Node 12.17.0 / 13.12.0+).
2. **`constructor.prototype`** — Every plain object inherits `constructor` from `Object.prototype`, pointing at the `Object` function. `Object.prototype` is reachable as `obj.constructor.prototype`. NOT disabled by `--disable-proto`. This is the residual attack surface even on hardened Node deployments.
3. **`prototype.prototype`** — For objects that *do* have a `prototype` field (functions, class instances), the chain extends further. Less common in practice but appears in some merge-into-class patterns.

A recursive-merge primitive that walks user input and assigns properties without checking the destination key is exploitable through any of these three. **Filtering only `__proto__` is incomplete.** The minimal correct allowlist is: `__proto__`, `constructor`, `prototype`.

### Why Map and Set are immune

`Map.prototype.get(key)` / `set(key, value)` do not walk a prototype chain when resolving keys — the map's internal `[[MapData]]` slot is accessed by structural identity (`SameValueZero`). `m.get("__proto__")` returns the value previously `m.set`'d under that exact key, or `undefined`. Sets behave the same. This is the single largest unforced error in JavaScript ecosystem APIs: most key-value stores ship as plain objects rather than Maps, because POJO literals are syntactically lighter and pre-ES6 idioms persist. Every config object, cache, memoization table, and middleware-options bag is a potential pollution sink.

### Why Object.create(null) defends

`Object.create(null)` returns a new object whose `[[Prototype]]` is `null` — no prototype chain at all. The object has no `toString`, no `hasOwnProperty`, no `__proto__` getter, no `constructor`. Property lookup falls through to `undefined` rather than walking to any prototype. The downside is exactly what makes it safe: code that calls `obj.hasOwnProperty(...)` on such an object throws `TypeError: obj.hasOwnProperty is not a function`. Application code must be written to use `Object.prototype.hasOwnProperty.call(obj, k)` or, post-ES2022, `Object.hasOwn(obj, k)` to inspect them safely. Many real-world codebases do not.

### The recursive-merge pattern as canonical source

The single recipe behind nearly every shipping pollution CVE:

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (typeof target[key] !== 'object') target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

Pass `source = JSON.parse('{"__proto__": {"polluted": "yes"}}')`. The loop enters `source.__proto__`, sees it is an object, recurses into `target["__proto__"]` (which resolves to `Object.prototype` via the getter), and assigns `polluted: "yes"` onto the global. Every subsequent `{}` in the process has `polluted === "yes"` until exit.

This is what `jQuery.extend(true, ...)` did before 3.4.0 (CVE-2019-11358 / CVE-2019-5428), what `lodash.merge` / `defaultsDeep` / `set` / `setWith` did before their respective fixes, what `minimist` did before 1.2.3 (CVE-2020-7598), what `Hoek.merge`, `dot-prop`, `set-value`, `deep-extend`, `nested-object-assign`, `merge-deep`, `mixin-deep`, and dozens of others did. Shape is identical; the difference between vulnerable and patched is three lines guarding the destination key.

### Object.assign and the shallow vs deep distinction

`Object.assign(target, source)` is NOT vulnerable on its own — it copies *own* enumerable properties; `source.__proto__` is inherited and skipped. **But** it *does* assign to `target["__proto__"]` if `source` was a parser output that produced `__proto__` as an *own* property. V8's native `JSON.parse` (since ~Node 12) creates `__proto__` as an own data property on the result. Other parsers (`js-yaml` before 3.14.2 / 4.1.1, `csv-parse` before 7.0.2 with `columns` and `group_columns_by_name`) can change the result object's prototype. The behavior depends on parser version and configuration. **Treat the question "does my parser put `__proto__` on the result as an own property" as unanswerable without testing the specific runtime; assume yes.**

### ECMAScript spec corner cases

- `Object.freeze(Object.prototype)` makes assignments to it silently fail in non-strict mode and throw in strict mode. Theoretically a process-wide defense; rarely used because legacy libraries patch `Object.prototype` at startup (e.g. some polyfills, instrumentation libraries).
- `Object.defineProperty(Object.prototype, '__proto__', {value: undefined, writable: false, configurable: false})` removes the setter half of the `__proto__` accessor. Closes one of the three reachability paths but breaks code that depends on `obj.__proto__` reads.
- ES2022's `Object.hasOwn(obj, k)` is the safe replacement for `obj.hasOwnProperty(k)`. Recommended in every modern post-pollution defensive guide.
- `Reflect.ownKeys(obj)` enumerates own properties (including symbol keys and non-enumerable), distinguishing them from inherited prototype properties.

---

## 2. Source Catalog — Where User Input Reaches a Merge Sink

The "source" in static-analysis terms is any code path that takes attacker-controlled bytes and produces a JavaScript object that will subsequently be merged, traversed, or used for property lookup. The exhaustive enumeration matters: many real-world cases of "we sanitize the body" miss query strings, hash fragments, header values, environment-derived config, and parsed file contents.

### 2.1 HTTP query string parsing

Libraries that parse `?a=1&b=2` into objects are sources if they support nested key syntax. Canonical example: `qs` used by Express's `bodyParser.urlencoded({extended: true})`: `?__proto__[polluted]=yes` produces `{__proto__: {polluted: "yes"}}` for downstream merge. Affected historically: `qs` (CVE-2017-1000048), `query-string`, `url-parse`.

### 2.2 JSON body parsing + recursive merge

Textbook path: Express + body-parser + a handler that calls `_.merge(defaults, req.body)`. Bentkowski's Kibana RCE (CVE-2019-7609) is this pattern via the Timelion expression evaluator. Shcherbakov's Parse Server / NPM CLI / Rocket.Chat RCEs are this pattern in model-hydration or configuration logic. `JSON.parse` is not the bug — it is a faithful parser. The bug is the unbounded merge of *attacker-controlled* JSON into *trusted* program state. Fix at the merge boundary: schema-validate before merge, or use a merger that skips `__proto__`/`constructor`/`prototype`.

### 2.3 YAML body parsing

`js-yaml`, `yaml`, `yamljs` produce ordinary JS objects; same merge sinks apply. Several YAML parsers historically supported `!!js/function` / `!!js/regexp` type tags producing live functions or regexes — an adjacent unsafe-deserialization class. `js-yaml` removed unsafe schema as default in v4.

### 2.4 URL fragment / hash parsing — canonical client-side source

For client-side pollution the predominant source is `document.location.hash` or `.search` parsed into a JS object. Visiting `https://victim/#__proto__[onerror]=alert(1)` is a one-click pollution if the SPA's hash router does deep parsing. BlackFan's repo catalogues ~30 libraries vulnerable through this source.

### 2.5 WebSocket / HTTP-2 / JSON-over-RPC

Same shape as 2.2; transport changes, parser-to-merge boundary is identical. Worth calling out because request-handling code is often outside the standard Express middleware chain and missed by guards added there.

### 2.6 LocalStorage / cookie parse-into-object

`document.cookie` parsing is one of the most common hand-rolled JS functions. Any parser that recurses into nested keys (`a.b.c=1` as nested structure) is a source. Same for `localStorage.getItem(...)` + `JSON.parse`.

### 2.7 DOM message events (postMessage payloads)

`window.addEventListener('message', e => merge(state, e.data))` appears with high frequency in bug-bounty writeups. Attacker is any cross-origin frame the page embeds (or that embeds the page). Defense: treat `e.data` as untrusted at the boundary.

### 2.8 File-based: package.json / config-file loaders

Build tools that merge user-controlled `package.json` into trusted build state (test harnesses, CI runners, monorepo orchestrators) are vulnerable if unguarded. Less common as a *remote* vector; more common as a supply-chain primitive — a malicious dependency's `package.json` pollutes the consuming build tool's prototype.

### 2.9 INI parsers — the path that produced CVE-2020-28472

Kurt Boberg's CVE-2020-28472 traced an INI-file parser inside `@aws-sdk/shared-ini-file-loader` to a recursive merge into a shared configuration object. The AWS SDK loads `~/.aws/credentials` and `~/.aws/config` at SDK initialization. Any application running with a writable home directory + AWS SDK initialization on a controlled trigger is exposed. The vulnerability shape:

```ini
[default]
__proto__.polluted = yes
```

The parser produced an object whose `__proto__` key was set as an own property, and the loader's merge logic walked into it. Patched in `@aws-sdk/shared-ini-file-loader` ≥ 1.0.0-rc.9 (and aws-sdk ≥ 2.814.0) by explicit key denylist. Advisory: [GHSA-rrc9-gqf8-8rwg](https://github.com/advisories/GHSA-rrc9-gqf8-8rwg). This case is structurally important: **a configuration loader that an application invokes implicitly at startup is a more dangerous source than a network-facing one**, because it expands the attack surface to anyone who can write into the loader's input files (local privilege escalation, container image supply-chain, malicious init script).

### 2.10 CLI argument parsers — minimist (CVE-2020-7598)

`minimist` is one of the most-downloaded npm packages; it parses argv into a config object. Versions pre-1.2.3 supported `--__proto__.polluted=yes` argv and propagated the assignment. Anyone consuming `minimist` to parse arguments from an untrusted source — environment variables that derive from HTTP headers, supervisor-passed argv lists in container orchestrators, JSON-RPC-to-CLI bridges — was exposed. Patched advisory: [GHSA-vh95-rmgr-6w4m](https://github.com/advisories/GHSA-vh95-rmgr-6w4m). `yargs-parser` had the parallel issue (CVE-2020-7608).

### 2.11 ORM / database hydration

Mongoose, Sequelize, and similar ORMs construct model instances from query results by assigning database-returned columns onto an object. If the schema allows arbitrary keys and a row contains a key named `__proto__`, hydration is a source.

### 2.12 Specific package-level sources to remember

Packages with documented pollution CVEs as *sources*: `lodash` (multiple CVEs through 4.17.20), `minimist`, `mixin-deep`, `set-value`, `deep-extend`, `hoek`, `qs`, `js-yaml` (pre-4 unsafe schema), `dot-prop`, `object-path` (Kurt's CVE-2021-3805), `immer`, `nested-object-assign`, `flat`, `xml2js`, `csv-parse` (column-mode), `aws-sdk` shared-ini-file-loader (Kurt's CVE-2020-28472), `jquery` (Kurt's CVE-2019-5428 / parallel CVE-2019-11358), `mongoose` (pre-5.13.15 query helpers). Most are patched in current versions. Their continued presence in legacy lockfiles is the operational risk.

---

## 3. Sink / Gadget Catalog (Server-Side, Node.js)

A "gadget" is a code site that *reads* a property from a polluted prototype and uses the read for a security-sensitive decision. Pre-Shcherbakov, the prevailing wisdom was that server-side pollution was mostly DoS — overwrite `toString` to throw, break the process. Shcherbakov's "Silent Spring" (USENIX 2023) demolished this view by demonstrating 11 universal gadgets in core Node.js APIs that escalate pollution to RCE without requiring application-specific code. The follow-up "GHunter" (USENIX 2024) added 56 more in Node and 67 more in Deno.

### 3.1 child_process: the canonical RCE gadget family

`child_process.exec(cmd, options)` and `spawn(file, args, options)` read properties from `options` if provided. If `options` is absent OR is `{}` whose lookups fall through to a polluted prototype, the attacker controls process spawning behavior. High-value polluted properties:

- **`options.env`** — Child process environment. `Object.prototype.env = {NODE_OPTIONS: "--require /tmp/evil.js"}` causes every subsequent Node spawn to execute attacker code via NODE_OPTIONS.
- **`options.shell`** — When truthy, `exec` runs through `/bin/sh -c` (or `cmd.exe`). Polluting with a malicious binary redirects all shell invocations.
- **`options.execArgv`** — Array of arguments prepended to Node's command line for subprocess spawns. `Object.prototype.execArgv = ["--eval", "require('fs').writeFileSync('/tmp/pwn','')"]` is direct RCE on any `fork` call.
- **`options.cwd` / `argv0` / `uid` / `gid`** — Working directory, process-name spoofing, and credential downgrades; less common but listed for completeness.

**NODE_OPTIONS via env is the most reliable cross-codebase gadget.** Many Node applications eventually call a library that spawns a child process (npm, git, ImageMagick wrappers, PDF renderers). A single pollution + a single spawn anywhere = RCE.

### 3.2 require() and the package.json main resolution gadget

Documented in Shcherbakov's paper: Node's module resolution algorithm, when given a directory, reads `package.json` from that directory and looks up the `main` property. If `package.json` does not define `main`, the lookup falls through to the prototype chain. Polluting `Object.prototype.main = "./../../pwned.js"` causes any subsequent `require('./some-directory-without-package-json-main')` to load `pwned.js` instead of the directory's `index.js`. This is a universal Node.js gadget independent of application code.

### 3.4 HTTP / HTTPS / Net agent gadgets

The KTH-LangSec gadget catalogue lists `http` / `https` `get` and `request` gadgets via polluted `hostname`, `headers`, `method`, `path`, and `port`, plus a `NODE_TLS_REJECT_UNAUTHORIZED` gadget for `https.get` / `https.request`.

### 3.5 Express / Connect-specific gadgets

- **`req.body` middleware ordering** — body-parser with `{extended: true}` + downstream `_.defaults(config, req.body)` lets body content pollute process state.

### 3.7 The "ignored option" rule

A pattern that recurs across Shcherbakov's catalogue: APIs taking options objects have many infrequently-used properties; callers pass only what they care about, leaving the rest to default. *Those defaults are the gadgets.* The lesson generalizes: **any API surface where "the caller passes some properties, the rest default" is a candidate gadget surface; the rest-of-properties is exactly the polluter's attack surface.** This is what makes "Silent Spring" structurally important — *the runtime itself* is full of these reads, in every options-bag API. The exposure is universal across Node.js applications.

### 3.8 Template engine RCE gadgets (EJS, Pug, Handlebars)

EJS reads `options.outputFunctionName` for the generated render function. Polluting it to malicious JavaScript yields RCE on the next render. EJS, Pug, Handlebars, and Underscore templates have variants of this gadget. Payload + a single render call anywhere = code execution.

---

## 4. Sink / Gadget Catalog (Client-Side)

Client-side prototype pollution typically chains pollution + DOM-XSS gadget. The pollution primitive is usually a hash-fragment parser; the gadget is a property read inside a library function that flows into `innerHTML`, `eval`, `setTimeout`, `setInterval`, `Function()`, or attribute injection.

### 4.1 jQuery

The single most prevalent client-side gadget surface. BlackFan's repo enumerates the chain: pollute `Object.prototype.context`, `jquery`, or `html` and `$.parseHTML`, `$.append`, or `$(html_string)` can be coerced into emitting attacker-controlled HTML. `$.extend(true, ...)` is BOTH a source (recursive merge) AND a downstream gadget host. The CVE-2019-11358 / CVE-2019-5428 fix in 3.4.0 addressed the source half; the gadget half remained.

### 4.2 AngularJS $compile and template gadgets

AngularJS interpreted template strings with expression-evaluation. Polluting properties read during compilation redirected template resolution to attacker-controlled markup. BlackFan's repo includes detailed Angular 1.x chains.

### 4.3 DOMPurify and sanitizer bypass

DOMPurify is the most-deployed client-side HTML sanitizer. Bentkowski's research and Cure53's own advisories ([GHSA-p3vf-v8qc-cwcr](https://github.com/cure53/DOMPurify/security/advisories/GHSA-p3vf-v8qc-cwcr), [GHSA-v9jr-rg53-9pgp](https://github.com/cure53/DOMPurify/security/advisories/GHSA-v9jr-rg53-9pgp)) document gadget paths where pollution + DOMPurify call yields XSS bypassing the sanitizer entirely. Structural issue: DOMPurify reads its configuration object's properties (`ALLOWED_TAGS`, `ALLOWED_ATTR`, `CUSTOM_ELEMENT_HANDLING.tagNameCheck`) via property access; polluting them on `Object.prototype` substitutes attacker-controlled allowlist values *during sanitization*. Deeper lesson: **a sanitizer cannot defend against pollution if its own configuration is reached through prototype lookup.** DOMPurify 3.4.0 added defensive `Object.create(null)` for config; earlier 3.0.x / 3.1.x versions in widespread deployment remain exposed.

### 4.4 React / Vue dangerously* paths

`React.createElement('div', {dangerouslySetInnerHTML: {__html: x}})` is the React XSS sink. If `x` is read from a polluted property, it is an XSS chain. Vue's `v-html` is the parallel. Chain in practice: pollute → some library reads polluted property as default HTML → flows to dangerouslySetInnerHTML.

### 4.5 CSP-bypass via polluted nonce / integrity

CSP `nonce-...` and `integrity-...` are per-request server-issued values. Some SPA frameworks read them from configuration objects; polluting those reads substitutes attacker-controlled values. Polluted `Object.prototype.nonce = "<attacker-known>"` + an injected script tag with the same nonce bypasses CSP.

### 4.7 PortSwigger Research catalogue

Gareth Heyes maintains a running catalogue at [portswigger.net/research](https://portswigger.net/research). The "Widespread prototype pollution gadgets" article (June 2022) enumerates gadgets in Google Tag Manager, Adobe DTM, Google Analytics, and others.

---

## 5. The Cross-Language Variant Class

Prototype pollution is named for JavaScript, but the recipe ports to any language with dynamic attribute resolution and a recursive-merge primitive that accepts untrusted input. The class is "deserialization-into-trusted-shape," and the JS variant is the canonical case study; conceptually adjacent to the unsafe-deserialization class covered in `~/ai/expertise/software/deserialization_expertise.md`.

### 5.1 Python class pollution

Python's class hierarchy is mutable at runtime. Any object instance has a `__class__` attribute pointing at its class; the class has a `__base__` (or `__mro__`) pointing at its parents. Walking `obj.__class__.__base__.__base__...` reaches `object`, the root of the class tree, and writing attributes there has the same global effect as `Object.prototype` in JS.

The vulnerable pattern is the same recursive merger that takes user input and walks `getattr(target, key) = setattr_recurse(getattr(source, key))` without guarding `__class__`, `__bases__`, `__globals__`, `__init__`, `__dict__`, or `__subclasses__`. The HackTricks "Class Pollution (Python's Prototype Pollution)" page enumerates the working exploit shapes against Flask/Werkzeug:

```python
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and isinstance(v, dict):
                merge(v, dst.get(k))
            else:
                dst[k] = v
```

User input `{"__init__": {"__globals__": {"SECRET_KEY": "attacker"}}}` walked through such a merger reaches Flask's app object via `__init__.__globals__.app.config['SECRET_KEY']`, allowing the attacker to substitute the session-signing key and forge sessions with arbitrary identity.

DeepDiff's CVE-2025-58367 ([GHSA-mw26-5g2v-hqw3](https://github.com/advisories/GHSA-mw26-5g2v-hqw3)) is a recent example: the Delta class accepts user-provided diffs and applies them by attribute setting, reaching across `__class__` to pollute parent classes.

### 5.2 Java / Kotlin reflection-based pollution

Java does not have the same dynamic-class-mutation surface, but Jackson polymorphic deserialization (covered in detail in `deserialization_expertise.md` §3) is conceptually the same primitive: untrusted input + a "deserialize into trusted shape" boundary + a reflective property-set loop = arbitrary type confusion. The defenses are also conceptually identical: schema validation before reflection (allowlist of accepted types), or eliminate the unsafe-by-default deserialization mode.

### 5.3 PHP object property pollution

PHP's recursive array_merge_recursive and analogous custom recursive mergers exhibit the same shape, though without a single global `Object.prototype` equivalent. Class-property mutation via Reflection API is possible but rarer in production code paths.

PHP's built-in `array_replace_recursive` / `array_merge_recursive` and Laravel's `Arr::set` (dot-notation nested set) are recursive-merge primitives; when called on user input without key validation, they can pollute config objects passed by reference downstream. Less impactful than JS due to PHP's request-isolated execution model — pollution is per-request, not process-wide — but still a vulnerability class.

### 5.4 Multi-language framing

The shared structural requirements: (1) language allows recursive attribute / property assignment by string key; (2) runtime has a shared parent object/class reachable via a well-known property name; (3) application code merges untrusted input into trusted state via that recursive pattern. Wherever all three hold, the bug class is real. JavaScript hits all three globally. Python hits all three with `__class__` and process-scope mutation. PHP hits two but with request-scoped impact. Go and Rust do not hit (1) directly — struct fields are statically typed — though `map[string]interface{}` and `serde_json::Value` reintroduce the surface at boundaries.

---

## 6. Detection — Static Analysis Lens

For static-analysis rule authors, prototype pollution is a clean taint-shaped class: small number of canonical sources, small number of canonical sinks, named-library-function bridges. The detection problem is principally *cataloguing* the source/sink set well, not designing novel analysis.

### 6.1 Source rules: identify recursive-merge primitives that accept user input

```yaml
# Lodash merge family on Express request body
- pattern-either:
    - pattern: _.merge($DST, req.body, ...)
    - pattern: _.merge($DST, req.query, ...)
    - pattern: _.merge($DST, req.params, ...)
    - pattern: _.defaultsDeep($DST, req.body, ...)
    - pattern: _.set($DST, $KEY, $VAL)
    - pattern: _.setWith($DST, $KEY, ...)
```

```yaml
# jQuery extend with deep=true and unfiltered input
- pattern: $.extend(true, $TARGET, $SRC)
- metavariable-pattern:
    metavariable: $SRC
    pattern-either:
      - pattern: JSON.parse($X)
      - pattern: req.body
```

```yaml
# object-path setIn / del (CVE-2021-3805 shape)
- pattern: objectPath.set($OBJ, $PATH, $VAL)
- pattern: objectPath.del($OBJ, $PATH)
```

For Kurt's CVE-2020-28472 shape (aws-sdk shared-ini): identify any parser-then-merge pipeline taking a file path derived from user-influenceable input (HOME, AWS_CONFIG_FILE, argv). Source is filesystem, not network; threat model is local-attacker / supply-chain.

### 6.2 Sink rules: identify reachable gadgets

Reads are not syntactically distinguishable from any other property access. Practical compromise: flag high-value sink calls (the Shcherbakov gadget set) that use a `{}` options literal OR omit options entirely:

```yaml
- pattern-either:
    - pattern: child_process.exec($CMD)
    - pattern: child_process.exec($CMD, $CALLBACK)
    - pattern: exec($CMD)
```

This emits false positives by design. The signal is the *combination* of a source firing AND a sink firing in the same codebase; the analyst correlates. Taint analysis at scale (Shcherbakov's CodeQL) is the principled solution; Semgrep is the cheap-and-fast triage layer.

### 6.3 The pattern-after-taint formulation

```yaml
mode: taint
pattern-sources:
  - pattern-either:
      - pattern: req.body
      - pattern: req.query
      - pattern: req.params
      - pattern: JSON.parse($X)
pattern-sinks:
  - pattern-either:
      - pattern: _.merge($DST, $SRC, ...)
      - pattern: _.defaultsDeep($DST, $SRC, ...)
      - pattern: $.extend(true, $TARGET, $SRC)
      - pattern: Object.assign($DST, $SRC)
pattern-sanitizers:
  - pattern-either:
      - pattern: ajv.validate($SCHEMA, $SRC)
      - pattern: $SCHEMA.parse($SRC)
      - pattern: $SRC.__proto__ = null
```

The sanitizer list must include any schema-validation or allowlist step the codebase uses; missing a real sanitizer is the noise source for false positives.

### 6.4 Reachability discipline

A polluted prototype is harmless unless a gadget exists in the same process. This is the *click-count* discipline from `~/ai/expertise/software/code_review_expertise.md` §1: pollution alone is zero-click DoS (high severity for stability but low for confidentiality); pollution + child_process gadget in the same process is zero-click RCE (CRITICAL). For server-side Node, the answer is almost always yes — npm itself spawns child processes, every Express app eventually invokes git or a system tool, template engines are everywhere. Treat any unguarded server-side pollution source as CRITICAL until ruled out by *demonstrating* the gadgets are unreachable. For client-side, the equivalent gating question is "does any property read flow to innerHTML / eval / Function() in any library on the page." With jQuery, AngularJS 1.x, DOMPurify pre-3.4, or any of the BlackFan-catalogued libraries on the page, the answer is yes. Corollary: **the same primitive can be MEDIUM in a tightly-controlled SPA and CRITICAL on a marketing page that loads ten third-party scripts.**

### 6.5 The "weak sanitizer" pattern

A pattern worth flagging in code review and rule authoring, paralleling the framing of `escapeshellcmd` covered in the memory `feedback-escapeshellcmd-weak-sanitizer.md`: many codebases include a string-matching guard like:

```js
if (key === '__proto__') continue;  // skip dangerous key
target[key] = source[key];
```

This is incomplete. It catches `__proto__` but not `constructor` and not `prototype`. The minimal correct denylist is `['__proto__', 'constructor', 'prototype']` and the guard must apply at every level of the recursive walk. A finding that says "this code defends against `__proto__` only" is HIGH severity by itself — the partial defense indicates the developer knew about the bug class but missed the reachable bypasses. Treat the partial sanitizer as a *signal* that the code is in scope, not as defense in depth.

---

## 7. Defensive Patterns

The order of preference for defenses, from strongest to weakest:

### 7.1 Object.create(null) for any user-input-derived object

The strongest single-line defense. Any object that will receive merged-in user input should be created with `Object.create(null)`:

```js
const config = Object.create(null);
Object.assign(config, defaults);
Object.assign(config, userInput);  // even if userInput has __proto__, config has none
```

Caveat: every property access on `config` must either avoid relying on inherited methods (no `config.hasOwnProperty(k)`) or wrap them through `Object.prototype.hasOwnProperty.call(config, k)` / `Object.hasOwn(config, k)`. In TypeScript, the type-checker will not catch this; tests and runtime assertions must.

### 7.2 Schema validation BEFORE merge

`ajv`, `joi`, `zod`, `yup` — any of these can be configured to reject objects containing `__proto__`, `constructor`, or `prototype` keys at validation time, before any merge. The recipe:

```js
const schema = z.object({
  email: z.string().email(),
  name: z.string().min(1),
}).strict();  // strict mode rejects any extra properties

const parsed = schema.parse(req.body);  // throws on __proto__
Object.assign(targetState, parsed);
```

`.strict()` is the load-bearing modifier. Without it, schemas accept extra keys silently and the pollution flows through to the merge.

### 7.3 Allowlist before recursive merge

For codebases that cannot adopt schemas wholesale, an explicit allowlist of accepted keys is the next-strongest defense:

```js
const ALLOWED_KEYS = ['email', 'name', 'preferences'];
function safeMerge(target, source) {
  for (const key of ALLOWED_KEYS) {
    if (Object.hasOwn(source, key)) target[key] = source[key];
  }
}
```

This trades flexibility for safety: the merge no longer accepts arbitrary nested shapes. For most application-level merges, this is the correct trade.

### 7.4 Object.freeze(Object.prototype) as a process-wide defense

```js
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);
```

The strongest "shut the bug class down" defense in the JavaScript portion of the codebase: any subsequent attempt to assign onto a frozen prototype throws in strict mode (or silently fails in sloppy mode). Caveats:

- Some libraries patch `Object.prototype` at load time (legacy polyfills, instrumentation tooling). Freezing breaks them.
- The freeze must happen *before* the first opportunity for any code to assign onto a prototype. In practice, that means the very first lines of the application's entry point, before any `require()` of user code.
- Some test frameworks (older Jest, Mocha) mutate prototypes for spy injection; freezing breaks tests.

Recommend with caveat: try it in a dev branch, run the full test suite, see what breaks, fix or document each break.

### 7.5 Node.js --disable-proto flag (Node 12.17+ / 13.12+)

`node --disable-proto=delete app.js` removes `__proto__` from `Object.prototype` entirely. `--disable-proto=throw` makes access to it throw `ERR_PROTO_ACCESS`. Either flag closes the `__proto__` path; the `constructor.prototype` path remains reachable.

Recommended as defense-in-depth: enable it in production. Combined with Object.freeze, the residual attack surface is small.

### 7.6 Audit-and-block known-vulnerable versions

Maintain a lockfile-level deny list against the canonical vulnerable versions: `lodash` < 4.17.21, `jquery` < 3.5.0, `minimist` < 1.2.6, `qs` < 6.10.3 (or the per-line backports such as 6.9.7 / 6.8.3 / 6.7.3), `yargs-parser` < 18.1.2, `set-value` < 4.0.1, `mixin-deep` < 1.3.2 (and 2.0.0), `deep-extend` < 0.5.1, `hoek` < 5.0.3, `object-path` < 0.11.8 (CVE-2021-3805), `@aws-sdk/shared-ini-file-loader` < 1.0.0-rc.9 (CVE-2020-28472), `dot-prop` < 5.1.1, `immer` < 9.0.6, `xml2js` < 0.5.0, `csv-parse` < 7.0.2.

Snyk's advisory database and `npm audit` cover this set automatically. Treat any `npm audit` finding of a CWE-1321 advisory as P1 unless reachability has been ruled out.

### 7.7 Modern alternatives: Map for key-value stores

When code is using a plain object as a key-value dictionary (not a structured record with named fields), prefer `Map` or `WeakMap`. Maps are not exposed to the prototype chain for key resolution and so are immune to the entire bug class.

Migration cost is real: `obj[k]` becomes `m.get(k)`, `obj[k] = v` becomes `m.set(k, v)`, `Object.keys(obj)` becomes `[...m.keys()]`. JSON serialization requires conversion. Most codebases adopt Map for new code and leave legacy POJO dictionaries in place.

### 7.8 Code-review checklist

1. Every recursive function that copies properties from source to destination: verify destination is not user-controlled, OR every key is in an allowlist before assignment.
2. Every call to `_.merge`, `_.defaultsDeep`, `_.set`, `_.setWith`, `$.extend(true,...)`, `mixin-deep`, `merge-deep`: verify the source argument is not directly user input.
3. Every `JSON.parse(userInput)` followed by use as a merge source: same verification.
4. Every `qs.parse`, `query-string.parse`, hand-rolled query parser: verify nested key syntax is disabled OR output is schema-validated.
5. Every options-object passed to `child_process.*`, `fs.*`, `http.*`, `template.render`, `require`: verify options are explicitly constructed (not `{}`), preventing fallthrough.
6. Every `Object.assign(target, src)` where `src` derives from user input: verify `target` is `Object.create(null)` or keys are allowlisted.
7. Every sanitizer invocation with a config object: verify config is `Object.create(null)` (DOMPurify, sanitize-html).
8. The partial-denylist anti-pattern: filters `__proto__` but not `constructor` and `prototype`. Finding this is a HIGH-severity signal.
9. TypeScript: structural typing means polluted shapes pass type checks; `as User` does not validate at runtime. Use `zod.parse()`.
10. Client-side: enumerate every library on the page; cross-reference BlackFan's gadget catalogue. If any catalogued library is present, treat any pollution primitive as a confirmed XSS chain.
11. Server-side: assume `child_process` or `require` is called somewhere in the dependency tree. If pollution is reachable, treat as confirmed RCE chain.
12. Pollution-related fixes: land at the *boundary* (merge function / schema check), not at individual call sites. Per-call-site fixes do not survive refactor.

---

## 8. The Server-Side Prototype Pollution Renaissance — Shcherbakov 2023

Pre-2023, the consensus position on server-side prototype pollution was "it's mostly DoS."

Mikhail Shcherbakov's "Silent Spring: Prototype Pollution Leads to Remote Code Execution in Node.js" (USENIX Security 2023, with Musard Balliu and Cristian-Alexandru Staicu) demolished this position by demonstrating that *Node.js itself* contains the gadgets — independent of any application code.

### 8.1 The 11 universal gadgets

The paper enumerates 11 gadgets in core Node.js APIs, all independent of application code: `child_process` command-execution APIs via polluted `shell` / `env` / `input` (see §3.1), `require` / `import` of a package without a declared `main` (see §3.2), `require` of a relative path via polluted `exports` / `1`, Windows path resolution via `'=C:'`, and `vm` function compilation via `contextExtensions`; two further gadgets combine these into command execution. A single prototype-pollution primitive in *any* application running *any* recent Node version is reachable to these gadgets.

### 8.2 The Silent Spring corpus

The paper's accompanying artifact ([github.com/KTH-LangSec/silent-spring](https://github.com/KTH-LangSec/silent-spring)) holds the CodeQL-based analysis and benchmarks; the paper manually exploits eight RCEs in three production apps: NPM CLI, Parse Server, and Rocket.Chat. Each is a multi-stage chain: untrusted entry point (a malicious package from the NPM registry for NPM CLI; stored database records for Parse Server) → injection sink (NPM CLI's `diffApply`; Parse Server's `expandResultOnKeyPath` record sanitizer) → gadget or attack sink (NPM CLI: `spawn` reading a polluted `env.GIT_SSH_COMMAND`; Parse Server: the MongoDB BSON parser's `evalFunctions`) → RCE.

### 8.3 The methodological shift

The paper's tool, a CodeQL-based static taint analysis, found pollution primitives at scale. Combined with its hybrid dynamic/static gadget detection, the analysis is now *universal*: any Node application with a pollution primitive is RCE-likely, regardless of application code.

### 8.4 GHunter (2024)

The follow-up "GHunter: Universal Prototype Pollution Gadgets in JavaScript Runtimes" (USENIX 2024, Cornelissen-Shcherbakov-Balliu) extended the methodology to Deno, using a V8-engine-instrumented dynamic taint analysis. The results: 56 new Node gadgets, 67 in Deno. The runtime-specific findings show that Deno's "secure by default" claim does not extend to prototype-reachable internal property lookups.

The cumulative position post-GHunter: **every JavaScript runtime is universally exposed to RCE-grade gadgets via prototype pollution.** There is no "safe Node version," no "safe runtime alternative," and no path to safety that does not begin with eliminating the pollution primitive at the boundary.

---

## 9. Variant Analysis — Under-Explored Substrates

### 9.1 Serverless (Lambda, Vercel, Cloudflare Workers)

Serverless platforms isolate invocations into separate process containers, so a pollution within one invocation does not persist to the next — in theory. In practice the "warm container" optimization means a single physical process serves many invocations *sequentially*, and pollution from invocation N persists to invocation N+1 on the same container. This is the largest unrecognized risk in serverless deployments today; the platform abstraction implies isolation that the runtime does not deliver. Cloudflare Workers is not an exception: a single Workers instance may handle multiple requests, including concurrent requests; Lambda's Node runtime likewise carries global state across invocations. Recommendation: assume warm-container pollution persistence; wipe state explicitly at handler entry; prefer `Object.create(null)` for per-request configuration.

### 9.2 Pollution via npm package post-install scripts

The npm `postinstall` lifecycle script runs arbitrary code in the developer's or CI's Node environment at install time. A malicious package can pollute `Object.prototype` of the install process; the pollution persists to subsequent build steps. Combined with bundlers that read configuration from prototype-reachable defaults, this is build-time RCE. Crosses into the supply-chain class; the org-wide CLAUDE.md package-manager cooldown policy is one of the threat models defending against this primitive.

### 9.3 Pollution via test fixtures

Jest, Mocha, and similar runners set up shared test state at process start. A test fixture that pollutes `Object.prototype` without resetting causes subsequent tests to run against a polluted runtime, producing both false-positive passes (pollution makes the code behave as the test expects, masking a real bug) and false-negative failures (pollution breaks an unrelated assertion). More dangerous: test fixtures sometimes leak into production builds when tree-shaking is incomplete.

### 9.4 ORM hydration pollution

Mongoose and Sequelize attach polluted properties to model instances during hydration. The model's `.save()` then writes attacker-controlled properties back to the database, *persisting* the pollution across process restarts and replicas. A one-shot pollution becomes a persistent backdoor. Defense: ORM strict mode (Mongoose `strict: 'throw'`), explicit field allowlists at model definition, and never trust returned model-instance keys for control-flow decisions without filtering.

### 9.5 TypeScript structural typing

TypeScript validates types structurally: any object that *looks* like a `User` is treated as one. A polluted object with the right shape — including extra prototype-planted properties — passes the type check. The `as User` assertion is a compile-time hint with no runtime validation. Many TypeScript developers believe `const u: User = req.body` provides safety; it does not. The byte-for-byte JavaScript is `const u = req.body`. Fix: runtime validation (zod, io-ts, runtypes) at the boundary, replacing the assertion.

### 9.6 The LLM-agent context

Polluted runtimes feed into LLM-agent tool implementations like any other Node code. An MCP server, an agent that calls Node-based tools, an Express backing an agent's tool API — all are vulnerable to pollution from input the agent processes. See `~/ai/expertise/software/llm_agent_security_expertise.md`: prompt-injection-as-source feeding into tool-output-as-context is structurally analogous to pollution-as-source feeding into gadget-as-sink. A prompt injection that causes an agent to make a tool call with `__proto__` in the payload pollutes the agent's runtime; subsequent tool calls run polluted. This is a real chain in agent systems with insufficient sanitization at the MCP-tool boundary.

---

## 10. References

### Original research (Arteau, Shcherbakov, Bentkowski)

- [Arteau, "Prototype pollution attacks in NodeJS applications" — NorthSec 2018](https://www.youtube.com/watch?v=LUsiFV3dsK8)
- [Arteau 2018 paper PDF](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20JavaScript%20Prototype%20Pollution%20Attack%20in%20NodeJS%20-%20Olivier%20Arteau%20-%202018.pdf)
- [Shcherbakov, Balliu, Staicu, "Silent Spring" — USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov) / [arXiv 2207.11171](https://arxiv.org/abs/2207.11171)
- [Cornelissen, Shcherbakov, Balliu, "GHunter" — USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/cornelissen) / [arXiv 2407.10812](https://arxiv.org/abs/2407.10812)
- [Bentkowski, "Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)"](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
- [Bentkowski, "Prototype pollution – and bypassing client-side HTML sanitizers"](https://securitum.com/resources/pentest-chronicles/prototype-pollution-and-bypassing-client-side-html-sanitizers)

### Client-side gadget corpora and tools

- [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) / [BlackFan/cspp-tools](https://github.com/BlackFan/cspp-tools)
- [s1r1us, "Prototype Pollution" research index](https://blog.s1r1us.ninja/research/PP)
- [PortSwigger, "Widespread prototype pollution gadgets" — Gareth Heyes](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
- [PortSwigger, "Server-side prototype pollution: Black-box detection without the DoS"](https://portswigger.net/research/server-side-prototype-pollution)
- [PortSwigger/server-side-prototype-pollution Burp extension](https://github.com/PortSwigger/server-side-prototype-pollution)
- [KTH-LangSec/server-side-prototype-pollution](https://github.com/KTH-LangSec/server-side-prototype-pollution) / [silent-spring](https://github.com/KTH-LangSec/silent-spring) / [ghunter](https://github.com/KTH-LangSec/ghunter)

### Sanitizer bypass advisories (Cure53 / DOMPurify)

- [GHSA-p3vf-v8qc-cwcr — tampering by prototype pollution](https://github.com/cure53/DOMPurify/security/advisories/GHSA-p3vf-v8qc-cwcr)
- [GHSA-v9jr-rg53-9pgp — PP-to-XSS via CUSTOM_ELEMENT_HANDLING fallback](https://github.com/cure53/DOMPurify/security/advisories/GHSA-v9jr-rg53-9pgp)

### Advisories crediting Kurt Boberg (GHSA analyst)

- [CVE-2021-3805 / GHSA-8v63-cqqc-6r2c — object-path `del()` pollution](https://github.com/advisories/GHSA-8v63-cqqc-6r2c) / [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-3805)
- [CVE-2020-28472 / GHSA-rrc9-gqf8-8rwg — `@aws-sdk/shared-ini-file-loader` pollution](https://github.com/advisories/GHSA-rrc9-gqf8-8rwg)
- [CVE-2019-5428 / GHSA-wv67-q8rr-grjp — jQuery pollution (jquery-rails RubyGems)](https://github.com/advisories/GHSA-wv67-q8rr-grjp)

### Canonical historical CVEs

- [CVE-2018-3721 / lodash — Arteau original](https://github.com/advisories/GHSA-fvqr-27wr-82fm)
- [CVE-2018-16487 / lodash — merge bypass (credited to asgerf)](https://github.com/advisories/GHSA-4xc9-xhrj-v574)
- [CVE-2019-10744 / lodash defaultsDeep](https://security.snyk.io/vuln/SNYK-JS-LODASH-450202)
- [CVE-2019-11358 / jquery — npm parallel to CVE-2019-5428](https://security.snyk.io/vuln/SNYK-JS-JQUERY-174006)
- [CVE-2020-7598 / minimist](https://github.com/advisories/GHSA-vh95-rmgr-6w4m)
- [CVE-2020-8203 / lodash zipObjectDeep](https://security.snyk.io/vuln/SNYK-JS-LODASH-567746)
- [CVE-2019-7609 / Kibana — Bentkowski's RCE](https://nvd.nist.gov/vuln/detail/CVE-2019-7609)
- [CVE-2025-58367 / DeepDiff — Python class pollution](https://github.com/advisories/GHSA-mw26-5g2v-hqw3)

### Defensive references

- [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [PortSwigger: "Preventing prototype pollution vulnerabilities"](https://portswigger.net/web-security/prototype-pollution/preventing)
- [MDN: "JavaScript prototype pollution"](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution)
- [nodejs-security.com: "Prevent Prototype Manipulation"](https://www.nodejs-security.com/learn/nodejs-runtime-security/prevent-prototype-manipulation)
- [Snyk Learn: "What is prototype pollution?"](https://learn.snyk.io/lesson/prototype-pollution/)
- [Snyk: "How to prevent prototype pollution vulnerabilities in JavaScript"](https://snyk.io/articles/prevent-prototype-pollution-vulnerabilities-javascript/)
- [MITRE CWE-1321](https://cwe.mitre.org/data/definitions/1321.html)

### Cross-language variants

- [HackTricks: Class Pollution (Python's Prototype Pollution)](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution.html)
- [Abdulrah33m: Prototype Pollution in Python](https://blog.abdulrah33m.com/prototype-pollution-in-python/)
- [lanmaster53.com: Prototype Pollution in Flask](https://www.lanmaster53.com/2023/02/01/prototype-polution-in-flask/)

### Cross-link to other expertise docs

- `~/ai/expertise/software/deserialization_expertise.md` — conceptually adjacent class (deserialize-into-trusted-shape); shared structural framing of Property-Oriented Programming and gadget chains; defenses share the schema-validation principle.
- `~/ai/expertise/software/code_review_expertise.md` — click-count severity discipline; the "weak sanitizer" pattern recognition; auth-homogeneity heuristics for property-walking code.
- `~/ai/expertise/software/llm_agent_security_expertise.md` — proto-pollution as a primitive in MCP/agent runtimes; the parallel of "untrusted bytes flow into trusted state without parsing boundary" across both classes.

### Memory cross-link

- `feedback-escapeshellcmd-weak-sanitizer.md` — parallel framing: a partial sanitizer is worse than none because it signals developer awareness of the bug class without correct mitigation. The `__proto__`-only denylist (catching the obvious key but missing `constructor` and `prototype`) is the prototype-pollution analogue.
