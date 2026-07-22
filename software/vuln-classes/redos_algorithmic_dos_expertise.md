# ReDoS and Algorithmic-Complexity DoS — Primitives and Defenses
## Synthesized from Scott Crosby & Dan Wallach, James C. Davis, Cristian-Alexandru Staicu, Michael Pradel, Yeting Li, Nicolaas Weideman & Brink van der Merwe, Russ Cox, Alexander Klink & Julian Wälde, John Graham-Cumming and Cloudflare engineering, Liran Tal and the Snyk research team, and Kurt Boberg

> **Researchers:**
> - **Scott A. Crosby and Dan S. Wallach (Rice University, 2003)** — "Denial of Service via Algorithmic Complexity Attacks," 12th USENIX Security Symposium. Foundational paper for the class. Demonstrated that any data structure engineered for average-case performance leaves a worst-case exploitable when the attacker controls input distribution: Perl 5.6.1 hash table (~6000x slowdown), Bro IDS pattern matching, Squid's hash-table DoS. The "computational complexity as attack surface" framing is the lineage every later paper inherits from.
> - **James C. Davis (Purdue ECE; formerly Virginia Tech)** — First author of "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale" (ESEC/FSE 2018, with Coghlan, Servant, Lee). Quantified ReDoS at ecosystem scale: extracted regexes from 448,402 npm and PyPI modules (>50% of each registry), classified by complexity, demonstrated existing CI tooling failed to catch them. Maintains `davisjam/vuln-regex-detector`, the canonical static+dynamic scanner. Also authored "SoK: A Literature and Engineering Review of ReDoS."
> - **Cristian-Alexandru Staicu (CISPA; formerly TU Darmstadt with Michael Pradel)** — First author of "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers" (USENIX Security 2018). Identified 25 previously unknown ReDoS vulnerabilities and tested 2,846 of the most popular websites; 339 (12%) were exploitable. Discovered CVE-2017-16042 (growl), CVE-2017-16119 (`fresh`, ships with Express), CVE-2017-15010 (`tough-cookie`).
> - **Michael Pradel (University of Stuttgart Software Lab; formerly TU Darmstadt)** — Co-author on "Freezing the Web" and PI of the Software Lab. Broader research program in JavaScript security (Synode, Nodest); the lab produced the largest set of ReDoS-PoC npm CVEs in 2017-2018.
> - **Yeting Li (Institute of Software, Chinese Academy of Sciences)** — First author of "ReDoSHunter" (USENIX Security 2021) and "RegexScalpel: ReDoS Defense by Localize-and-Fix" (USENIX Security 2022). Among 448 vulnerable regexes from production code, RegexScalpel repaired 443 (98.88%); prior state-of-the-art repaired 95 (21.20%). First work to handle backreferences and lookarounds — the features that put regexes outside RE2's regular-language frontier.
> - **Nicolaas Weideman and Brink van der Merwe (University of Stellenbosch)** — Authors of "Analyzing Matching Time Behavior of Backtracking Regular Expression Matchers by Using Ambiguity of NFA" (CIAA 2016) and "Turning Evil Regexes Harmless" (SAICSIT 2017). Automata-theoretic foundation of static ReDoS detection: classify an NFA by ambiguity (finite, polynomially-ambiguous, exponentially-ambiguous) to determine worst-case matching time. Tool: `github.com/NicolaasWeideman/RegexStaticAnalysis`. Most production ReDoS scanners are downstream of this lineage.
> - **Russ Cox (Google)** — Author of the "Regular Expression Matching" series at swtch.com/~rsc/regexp/ (2007-2010). Designer of RE2, the Thompson-NFA-based regex engine adopted by Go, Rust, and Cloudflare (post-2019). The canonical argument that backtracking engines are an engineering mistake whenever attacker influence on pattern or input is possible.
> - **Alexander Klink and Julian Wälde (n.runs AG, 2011)** — Presented "Efficient Denial of Service Attacks on Web Application Platforms" at 28C3. Demonstrated that nearly every server-side web platform (PHP, Java, ASP.NET, Python, Ruby, V8) processed HTTP POST parameters into a fixed-seed hash table with predictable collisions, leaving every platform vulnerable to single-request CPU-exhaustion. CVE-2011-4885 (PHP), CVE-2011-3414 (ASP.NET, MS11-100), and the ecosystem-wide migration to randomized hash seeds (Python PEP 456, Ruby 1.9.3, Perl 5.18) and treeified buckets (Java 8 JEP 180).
> - **John Graham-Cumming and Cloudflare engineering (2019)** — "Details of the Cloudflare outage on July 2, 2019." Canonical public-incident-of-record for ReDoS in a production WAF: a single regex deployed globally in simulate mode caused 27 minutes of near-total outage, 80%+ traffic loss, CPU pinned at ~100% across the edge. The trailing fragment `.*(?:.*=.*)` exhibited catastrophic backtracking on benign inputs. Remediation: replace PCRE-based Lua WAF with RE2 or Rust-regex; staged rollouts; emergency kill-switch.
> - **Liran Tal and Snyk Research** — Director of Developer Relations at Snyk; author of "Regular Expression Denial of Service and Catastrophic Backtracking" and annual "State of Open Source Security" reports quantifying ReDoS prevalence in npm year-over-year. Snyk's vulnerability database is the de-facto canonical ReDoS CVE catalogue.
> - **Kurt Boberg (GHSA reporter `kurt-r2c`)** — Staff Security Researcher at Semgrep. Six publicly-credited CVEs in the cluster: **CVE-2018-3739** `https-proxy-agent` (GHSA-8g7p-74h8-hg48); **GHSA-7wwv-vh3v-89cq** `highlight.js` (ReDoS across 35+ grammars); **CVE-2022-29546** NekoHtml (GHSA-6jmm-mp6w-4rrg); **CVE-2022-33082** Open Policy Agent (GHSA-2m4x-4q9j-w97g); **CVE-2022-26924** Microsoft YARP (GHSA-8xc6-g8xw-h2c4); **CVE-2022-40151** XStream (GHSA-3mq5-fq9h-gj7j).
>
> Sources: usenix.org/legacy/events/sec03; davisjam.github.io; staicu.org; software-lab.org; yetingli.github.io; github.com/NicolaasWeideman/RegexStaticAnalysis; swtch.com/~rsc/regexp/; fahrplan.events.ccc.de/congress/2011; blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/; snyk.io/blog/redos-and-catastrophic-backtracking/; github.com/advisories; nvd.nist.gov; x-stream.github.io/CVE-2022-40151.html.

---

## 1. The Primitive — Algorithmic Complexity as Attack Surface

### Average-case engineering vs worst-case exploitation

Nearly every shipping data structure is benchmarked around average-case performance. Hash tables, balanced trees, regex engines, parsers, sort routines, JSON schema validators — each has a worst case acceptable in random or adversary-blind workloads but catastrophic when an attacker controls the input distribution. Hash tables degenerate to linked lists. Backtracking regex engines exponentially blow up on patterns whose surface syntax looks innocuous.

The attack model is asymmetric: a ~1KB request can pin a CPU core for seconds or minutes. In a worker-pool deployment, a handful of such requests saturate the pool and the load balancer's health checks fail, cascading into total unavailability. In autoscaling environments the cost transfers to the cloud bill — a money-DoS attack. In per-request-billed serverless (Lambda, Cloudflare Workers, Vercel), the per-request runtime cap converts an availability attack into a budget-draining attack.

### Why this matters more now than in 2003

1. **Public attack surface is larger.** Every HTTP API parses untrusted bodies, query strings, headers, cookies. Each parser and each regex in a route matcher, validator, or middleware filter is a candidate ReDoS surface.
2. **Single-threaded runtimes (Node, Deno, Python's GIL, Ruby's MRI) amplify per-request blast radius.** A 30-second regex stalls all in-flight requests on that worker.
3. **Tail-latency SLOs are stricter.** A modern p99 ~200ms target is bypassed by any attack that adds seconds to a single request.

### The service-degradation cascade

One slow request pins one worker. N concurrent slow requests saturate the pool. The LB's per-worker health check times out; workers marked unhealthy; healthy workers receive elevated traffic; autoscaler is slow to react. The cascade tips: every worker is either pinned or being retried against; LB drops to "no healthy upstreams"; service is hard-down.

Cloudflare's July 2 2019 incident is exactly this cascade at planetary scale: a single regex deployed to every edge POP simultaneously pinned every CPU core within minutes; 80% of traffic dropped; recovery required the global kill-switch.

### Why this is structurally distinct from "slowness"

Normal performance bugs — unindexed queries, N+1 fetches — degrade gracefully with input size and surface under realistic load. Algorithmic-DoS bugs hide because they ride on a single pathological input. Load tests with normal traffic distributions never trigger them. Production telemetry shows median latency unchanged; only p99.99 or p99.999 reveals the worst case, and most teams don't alert at that resolution.

---

## 2. ReDoS — The Canonical Instance

### Why backtracking engines exponentiate

PCRE, Perl, Python `re`, Java `java.util.regex`, Ruby `Regexp` (pre-3.2), JavaScript V8, .NET `Regex` — all implement regex matching by simulating an NFA via depth-first backtracking. When a pattern reaches a choice point (alternation, quantifier), the engine tries one branch, and on failure backtracks. For patterns where choices overlap and the input maximizes failed attempts before final rejection, the engine explores exponentially many paths.

The Russ Cox 2007 essay (swtch.com/~rsc/regexp/regexp1.html) is the canonical demonstration: matching `a?a?a?...a?aaa...a` (n `a?` followed by n `a`) against `aaaa...a` (n `a`s) against backtracking Perl takes time `2^n`. Against Thompson's NFA-simulation (RE2's foundation), it completes in linear time. The Thompson construction (1968) is older than every shipping backtracking engine; the engineering choice to use backtracking was driven by feature compatibility (backreferences, lookarounds) rather than performance.

### The three vulnerable patterns

Davis, Weideman, and Li converge on the same taxonomy:

**1. Nested quantifiers — `(a+)+`, `(a*)*`, `(\d+)*`.** A quantifier applied to a group that itself contains a quantifier. For `aaaa...!` (n `a`s plus non-matching char), the engine partitions the `a`s in `2^(n-1)` ways before concluding no match. Exponential. Textbook ReDoS; static analyzers flag instantly. Easiest shape to write by accident.

**2. Alternations with overlap — `(a|aa)+`, `(\w|\d)+`.** Alternation branches that overlap create the same backtracking explosion as nested quantifiers. The overlap is often non-obvious: `(\w|\d)+` overlaps because `\d ⊂ \w`. Many real ReDoS instances are alternation overlap, not nested quantifiers.

**3. Greedy match with deferred validation — `^(\w+\s?)+$`, `.*(\w+)*.*`.** A greedy quantifier consumes most of the input, then a trailing constraint forces backtracking through every greedy/non-greedy split. The Cloudflare 2019 regex is this shape: `.*(?:.*=.*)` redistributes greedy `.*` consumption combinatorially.

### Polynomial vs exponential

- **Exponential ReDoS**: `O(2^n)` or `O(c^n)`. Triggered by nested or overlapping quantifiers without anchoring. Rare in practice (Davis: ~3% of vulnerable regexes); devastating — ~50 chars of input takes hours.
- **Polynomial ReDoS**: `O(n^k)` for `k >= 2`. Most real-world vulnerable regexes (~97% per Davis). ~100KB of input takes seconds; with worker pools, sufficient for service-wide DoS.

**Defensive implication: do not assume "only exponential ReDoS matters."** A `k=3` regex on a 100KB input field is a working primitive. Most ReDoS CVEs in npm and PyPI are polynomial.

### Per-language regex engine inventory (May 2026)

| Runtime | Engine | Algorithm | Timeout? | Notes |
|---|---|---|---|---|
| JavaScript V8 (Node, Chrome) | Irregexp | Backtracking | No built-in | Lookbehind 2018 (ES2018); no per-match timeout API. Cloudflare wrote `re2` Node bindings; most apps don't. |
| JavaScript SpiderMonkey (Firefox 78+) | Irregexp (forked) | Backtracking | No built-in | Replaced YARR in Firefox 78 (2020). Same algorithmic profile as V8. |
| Python `re` (CPython) | Custom backtracker | Backtracking | No built-in | `re.compile` does not help — compilation caches the NFA, not the matching strategy. |
| Python `regex` (PyPI 3rd-party) | Custom | Backtracking with better cutoffs | `timeout` keyword (2025+) | Strict superset of `re` features; partial ReDoS mitigation. |
| Java `java.util.regex` | Custom | Backtracking | No built-in for `Matcher` itself; `InterruptibleCharSequence` workaround | OpenJDK enhancement requests JDK-8268854 and JDK-8234713 remain open. Use `InterruptibleCharSequence` + thread interrupt for timeout. |
| Ruby `Regexp` (pre-3.2) | Onigmo | Backtracking | No | |
| Ruby `Regexp` (3.2+, Dec 2022) | Memoized backtracker | Memoization-based | `Regexp.timeout=` global; `timeout:` keyword per-regex | ~90% of regexes become linear-time via memoization; remainder bounded by timeout. Backreferences and some lookarounds excluded from memoization. |
| PHP PCRE | PCRE2 | Backtracking | `pcre.backtrack_limit`, `pcre.recursion_limit` | INI-tunable. Partial mitigation: limits the worst case but doesn't prevent slow-but-bounded ReDoS. |
| .NET `Regex` | Custom | Backtracking, with optional non-backtracking `NonBacktracking` mode (.NET 7+) | `MatchTimeout` constructor since 4.5; `RegexOptions.NonBacktracking` since 7.0 | Best per-language mitigation story of any backtracking engine. Use `NonBacktracking` for any regex on untrusted input. |
| Go `regexp` | RE2 | Thompson NFA | Linear-time by construction | Not vulnerable to classical ReDoS. No backreferences, no lookarounds — the trade for safety. |
| Rust `regex` crate | RE2-style | Thompson NFA | Linear-time | Same as Go. Adopted by Cloudflare post-2019. |
| Rust `fancy-regex` | Hybrid | Backtracking for back-refs, RE2 for the rest | Configurable size limits | When you need lookbehinds and backreferences in Rust. |
| Erlang `re` | PCRE2 wrapper | Backtracking | `{match_limit, N}` option | Per-call match-limit; underused. |

### The "use a linear-time engine" defense

Russ Cox's argument (swtch.com/~rsc/regexp/regexp1.html) is structural: a backtracking engine on untrusted input is not a performance bug, it is a design bug. The DFA-simulation approach (RE2, Go `regexp`, Rust `regex`) gives up two features in exchange for linear-time guarantees:

1. **Backreferences (`\1`, `\2`)**: not regular-language constructs; can only be matched in polynomial-or-worse time even with the most advanced algorithms. If you need them, you have left the regular-language frontier and accepted exponential worst-case behavior.
2. **Lookbehinds and lookaheads with variable width**: more recently the RE2-style engines have partial support, but the original argument holds — these features push you back into backtracking territory.

For 95%+ of production regex use (input validation, route matching, log parsing, data extraction), neither feature is needed. The Cox argument is: when you don't need them, **use a regex engine that doesn't offer them**, because offering them forces the engine to use a backtracker even for patterns that don't use the features.

---

## 3. Kurt's CVE Corpus in This Cluster

Six publicly-credited CVEs / GHSAs span the cluster from classical ReDoS through parser-shape DoS. Each is a different shape of the same underlying class: a parser or matcher whose worst-case complexity is exploitable by attacker-controlled input.

### CVE-2018-3739 — `https-proxy-agent` proxy-auth DoS (GHSA-8g7p-74h8-hg48, CVSS 9.1)

**Pattern.** `https-proxy-agent` <2.2.0 passed `proxy.auth` directly to legacy `Buffer(value)`. Legacy `Buffer(N)` with a numeric argument allocates uninitialized memory; with a string/object, behavior depends on coercion. An attacker influencing proxy config could submit a value coerced to a large integer, forcing gigabyte-scale uninitialized allocations — CPU-exhausting and a memory-disclosure primitive (uninitialized heap content may contain keys, source code, environment data).

**Exploit.** `proxy.auth = {valueOf: () => 1e9}` produces a billion-byte allocation. The advisory's "DoS" framing understates the dual nature: uninitialized-memory disclosure is the more serious primitive.

**Fix.** Switch ambiguous `Buffer(arg)` to disambiguated `Buffer.from(arg)`. Same fix that resolved dozens of Node.js `Buffer()`-misuse CVEs in 2017-2018.

**Lesson.** A constructor whose behavior depends on the runtime type of a single argument is an algorithmic-DoS hazard when an attacker influences the type. Same class as `new Date(userInput)` and `JSON.parse` with reviver functions.

### GHSA-7wwv-vh3v-89cq — `highlight.js` multi-grammar ReDoS

**Pattern.** `highlight.js` 9.0.0 through 10.4.0 shipped grammars (one per language) where 35+ contained at least one ReDoS-vulnerable regex. 14 grammars had exponential backtracking (C/C++, Arduino, Handlebars, GAMS, Perl, JBoss-CLI, R, Erlang-REPL, PowerShell, RouterOS, LiveScript, JavaScript, TypeScript); 22 had polynomial (Kotlin, G-code, D, AspectJ, MoonScript, CoffeeScript, C#, Scilab, Crystal, Elixir, BASIC, EBNF, Ruby, Fortran, LiveCode, YAML, x86 ASM, dsconfig, Markdown, RulesLanguage, XQuery, SQF).

**Exploit.** Widely deployed in client-side rendering of user-submitted content. `hljs.highlightAuto(userContent)` iterates through registered grammars trying each. A single user-submitted code block that hits the exponential worst case in any registered grammar freezes the rendering thread. In SSR contexts (Next, SvelteKit, Astro), this is the request handler.

**Why the multi-grammar surface matters.** The case study for "your DoS surface is the union of every regex you transitively load." The `highlight.min.js` bundle registers all 190+ grammars by default. The attacker doesn't need to know which grammar contains the bad regex; `highlightAuto` tries every one.

**Fix.** 10.4.1 rewrote vulnerable regexes — anchored-non-greedy form, or replacing regex-based parsing with hand-written state machines (e.g. JavaScript template literals).

**Lesson.** When you ship a library that registers regexes against untrusted input, your security model is the worst regex in your entire grammar inventory.

### CVE-2022-29546 — NekoHtml processing-instruction OOM (GHSA-6jmm-mp6w-4rrg, CVSS 7.5)

**Pattern.** NekoHtml 2.60.0 and earlier allocated unbounded heap memory when parsing crafted XML processing instructions (`<?target data?>`). The PI-handling path accumulated content into a growable buffer without bounding max size or max PI count per document.

**Exploit.** A single HTML document containing a large or deeply-nested PI causes `OutOfMemoryError` and kills the JVM. Per-request, independent — every request hitting a NekoHtml path is its own kill.

**Why this matters.** NekoHtml is widely embedded in Java content-extraction pipelines: Apache Nutch, multiple SAST tools, several Atlassian products. Transitive-dependency blast radius. Structurally identical to billion-laughs entity expansion — different XML construct being amplified.

**Fix.** 2.61.0 added bounded-buffer logic to the PI parser.

**Lesson.** Every parser construct that accumulates input is a candidate for resource-exhaustion DoS. Input-size limits, depth limits, allocation-count limits belong at the parser layer, not the application layer. Cross-link `xml_parser_differential_expertise.md`.

### CVE-2022-33082 — Open Policy Agent AST-parser DoS (GHSA-2m4x-4q9j-w97g, CVSS 7.5)

**Pattern.** OPA <0.42.0 had algorithmic complexity in `ast/compile.go`. Crafted Rego policy triggered exponential time in the compiler. Anyone able to submit policies (OPA's HTTP API, partial-evaluation requests, any code path compiling attacker-influenced Rego) could consume unbounded compile-time CPU.

**Exploit.** OPA is the de-facto policy engine for Kubernetes admission control (Gatekeeper), service-mesh authz (Istio, Linkerd), CI/CD policy checks. Surface depends on deployment: Gatekeeper policies are admin-controlled; OPA's REST API accepts policies from anyone with API access; in some test/dev configurations the API is unauthenticated. A single malicious policy pins the evaluator.

**Why this matters.** Rego is Turing-complete-adjacent (recursive references through the rule graph); the compiler must do non-trivial graph analysis. "User-supplied policy" plus "complex compiler" looks like ReDoS but operates one level up the abstraction stack. Treat policy engines like compilers — they are.

**Fix.** 0.42.0 added validation checks earlier; rejected certain Rego shapes before the exponential codepath.

**Lesson.** Any service that accepts user-defined logic (DSLs, expression languages, policy engines, GraphQL, SQL) inherits the complexity of its compiler. Cross-link `llm_agent_security_expertise.md` — LLM-generated tool-call DSLs are user-influenced policy.

### CVE-2022-26924 — Microsoft YARP reverse-proxy input DoS (GHSA-8xc6-g8xw-h2c4, CVSS 7.5)

**Pattern.** YARP (Yet Another Reverse Proxy) is Microsoft's .NET-native reverse proxy, used in ASP.NET-based gateways and Azure components. 1.0.0 and 1.1.0-rc.1.22152.1 had a DoS-grade input-handling flaw. The MSRC advisory is sparing on detail; most plausible mechanism given the patch is header-parsing quadratic in header count/value length, or path-normalization backtracking over crafted segments.

**Why this matters.** Reverse proxies sit before authentication and before application-layer defenses. A proxy DoS is a DoS of every downstream service. The attacker doesn't compromise any backend — just sends a request the proxy itself can't finish processing.

**Fix.** 1.0.1 and 1.1.0-rc.1.22211.2 added input validation/bounds.

**Lesson.** Position matters as much as severity. A medium-CVSS bug in a position-of-trust component (reverse proxy, LB, service mesh, API gateway) is high-impact in application context. Audit them with the same rigor as backends.

### GHSA-3mq5-fq9h-gj7j / CVE-2022-40151 — XStream uncontrolled-recursion parser crash

**Pattern.** XStream 1.4.19 and earlier had no depth tracking in `TreeUnmarshaller.startElement`, the recursive XML-element callback. Any deserialization entry point (`fromXML`, `unmarshal`, etc.) could be DoS'd via a deeply-nested document that exhausted the JVM call stack and threw `StackOverflowError`.

**Exploit.** `<a><a><a>...</a></a></a>` with ~10,000-50,000 levels overflows the default 256KB JVM thread stack. Bytes-per-stack-frame ratio favors the attacker: 3 bytes per `<a>` opening tag vs 100-200 bytes per stack frame. A 100KB payload overflows multi-megabyte stacks.

**Why this matters.** XStream is widely deployed in Jenkins, JIRA, and a long tail of enterprise Java. Many deployments accept untrusted XML — and have already-published deserialization gadget chains. This DoS is the lower-severity sibling of the XStream RCE class; same broken trust assumption. Cross-link `deserialization_expertise.md`.

**Fix.** 1.4.20 added explicit depth tracking with a configurable maximum (default 1024).

**Lesson.** Recursive parsers without depth bounds are stack-overflow primitives. The fix pattern (configurable depth limit) applies uniformly: `java.beans.XMLDecoder`, Jackson polymorphic types, Kryo, Hessian all share the structural vulnerability if depth isn't bounded.

---

## 4. Hash Flooding — The Under-Modeled Cousin

### The Crosby/Wallach original framing

The 2003 paper's headline was not regex — it was hash flooding. Perl 5.6.1's hash table slowed by ~6000x when populated with keys hashing to the same bucket. Perl's hash function was deterministic and public; an attacker computing colliding keys offline could submit a request populating an internal table (route lookup, parameter map) and force every insertion to walk the bucket's collision list, converting `O(1)` insert to `O(n)` and total population to `O(n^2)`. This structural shape recurs across every dynamic-language platform.

### Klink/Wälde 2011 — the rerun

Eight years later, Klink and Wälde at 28C3 demonstrated PHP, Java (Tomcat/Jetty), ASP.NET, Python, Ruby, V8 were all still vulnerable through HTTP POST parameter parsing. The mechanism was identical to 2003; **none of the major platforms had patched it**. A single POST with ~1MB of crafted parameter names consumed minutes of CPU.

CVEs and fixes:
- **CVE-2011-4885 (PHP)** — fixed in 5.3.9 via `max_input_vars` (default 1000) — capping parameter count rather than addressing hash determinism.
- **CVE-2011-3414 (ASP.NET, MS11-100)** — emergency MS advisory; parameter-count cap.
- **CVE-2011-5034 (Jetty), CVE-2011-5035 (Tomcat)** — similar caps.
- **PEP 456 / Python 3.4+** — SipHash-based randomized hashing for `str`/`bytes`/`datetime`. Proper structural fix.
- **Ruby 1.9.3** — randomized hash seed.
- **Java 8 / JEP 180** — HashMap treeification: buckets >8 collisions promote to Red-Black trees, converting `O(n)` collision-walk to `O(log n)`. Mitigation, not structural fix.

### Why hash flooding still works in 2026

Stdlib randomization is near-universal, but the broader class survives in:
- **Custom hash tables** — wherever a library rolled its own (HFT, game engines, custom DBs, pre-stdlib-hardening code).
- **Crypto primitives misused as keys** — tables keyed by SHA-1/MD5 prefixes remain vulnerable even when the table uses SipHash internally.
- **Some high-performance JSON parsers** — `simdjson`, `RapidJSON` may not randomize internal object-key tables.
- **HTTP/2 HPACK** — multiple 2020-2022 CVEs exploit HPACK state explosion; adjacent class.
- **QUIC connection-ID tables** — NCC Group's 2023 advisory documented hash-flooding across multiple QUIC implementations. New protocols re-introduce the old bug class.

### The "compute-bound input" framing

The general class is "any parser/lookup whose worst-case complexity is exposed to untrusted input." Hash tables are one instance; others include JSON parsing (deeply-nested triggers recursive descent; some parsers have `O(n^2)` parsing), JSON Schema validators with `oneOf`/`anyOf`/`allOf` combinatorics, YAML alias expansion (billion-laughs-for-YAML), XML entity expansion (cross-link `xml_parser_differential_expertise.md`), compression bombs (gzip/zstd/brotli with no output-size cap), Markdown rendering edge cases, HTTP header-count/value-length flooding.

The pattern: **any input-driven loop, parse, or table-lookup whose worst-case cost is super-linear in input size is a candidate attack surface.** Treat "what is my parser's worst case?" as a primary security-review question, not a performance one.

---

## 5. Discovery — Finding ReDoS at Scale

### The Davis lineage — static extraction + classification

`vuln-regex-detector` (github.com/davisjam/vuln-regex-detector) is the canonical open-source detector. Three stages:

1. **Static extraction** — AST-walk every JS and Python file; collect regex literals and constant-arg dynamic regexes.
2. **Classification** — query the ambiguity-analysis tool from the Weideman lineage; returns `safe`, `polynomial`, or `exponential`.
3. **Dynamic validation** — for flagged regexes, generate an attack string and run against the regex with a timeout. Bridges "structurally bad shape" to "demonstrated exploit."

Davis 2018 applied this to 448,402 npm and PyPI modules: 12,000+ vulnerable regexes found; ~50% extractable statically; runtime-constructed regexes remained a measurement blind spot.

### The Weideman/van der Merwe lineage — ambiguity-based classification

A regex's worst-case matching time is determined by its NFA's ambiguity profile: finite ambiguity → linear matching; polynomial ambiguity → polynomial matching; exponential ambiguity → exponential matching. `RegexStaticAnalysis` (github.com/NicolaasWeideman/RegexStaticAnalysis) implements this. Anyone implementing a custom scanner should read Weideman's Stellenbosch 2017 thesis first.

### The Li lineage — repair, not just detection

ReDoSHunter (USENIX 2021) and RegexScalpel (USENIX 2022) extend detection to automated repair. RegexScalpel's localize-and-fix: identify the specific NFA sub-structure responsible for ambiguity, apply a repair pattern from a catalog (atomic grouping, possessive quantifiers, anchoring, alternative restructuring), validate same regular language. 98.88% of vulnerable real-world regexes auto-repair. Blockers: regexes using backreferences in load-bearing ways, regexes whose semantics depend on backtracking order.

### Semgrep rule shapes for ReDoS detection

Naive but effective patterns for static SAST detection (cross-link `semgrep_rule_authoring.md`):

```yaml
# Detect nested-quantifier shapes in JS/Python/Java string-regex literals
- id: nested-quantifier-regex
  patterns:
    - pattern-either:
      - pattern-regex: '\([^)]*[+*]\)[+*]'
      - pattern-regex: '\([^)]*\{\d+,\d*\}\)[+*]'
  languages: [javascript, typescript, python, java, ruby, go]
  message: Nested quantifier — likely ReDoS-vulnerable

# Detect alternation-overlap shapes
- id: alternation-overlap-regex
  pattern-regex: '\((?:[a-zA-Z0-9\\]+\|){1,5}[a-zA-Z0-9\\]+\)[+*]'
  message: Alternation with potential overlap — manual review for ReDoS

# Detect greedy-with-trailing-constraint
- id: greedy-trailing-constraint
  pattern-regex: '\.\*[^$].*\.\*'
  message: Greedy .* with trailing match — candidate for catastrophic backtracking
```

These patterns are intentionally aggressive (high recall, lower precision). They are first-pass shape detectors; pair them with the Davis `vuln-regex-detector` pipeline for exploitability validation.

### CodeQL ReDoS query suite

CodeQL ships `js/redos`, `js/polynomial-redos`, `py/redos`, `py/polynomial-redos`, `java/redos`, `java/polynomial-redos`. These use dataflow analysis to confirm the vulnerable regex is reached by user-controlled input — converting "shape detection" into "reachable shape detection." Substantially lower FP rate. Recommended when CI already runs CodeQL.

### Developer-time vs production-time

Both lanes are required for defense-in-depth. **Developer-time** (pre-commit, CI, PR review): never ship a vulnerable regex — `vuln-regex-detector` or CodeQL in CI, fail the build on detection. **Production-time** (runtime): bound the damage when a vulnerable regex slips through — per-match timeouts, worker isolation, per-request CPU budgets. Static detection catches textbook cases; runtime bounding catches what escapes (dynamic regex construction, dependency regexes, config-loaded regexes).

---

## 6. Detection — Runtime / Production

### Per-language timeout configuration

**Ruby (3.2+).** `Regexp.timeout = 1.0` (global); `Regexp.new("...", timeout: 0.1)` (per-regex). The 3.2 memoization engine eliminates ~90% of ReDoS algorithmically; timeout is the fallback. Production Ruby should set `Regexp.timeout` at boot.

**Java.** No native `Pattern.matcher` timeout. Standard pattern: wrap input in an `InterruptibleCharSequence` whose `charAt(int)` checks `Thread.interrupted()` and throws. Submit the match to an executor; cancel on timeout. The engine calls `charAt` frequently during backtracking, so interrupt-propagation works.

**Python.** `re` has no timeout. The third-party `regex` module (PyPI) supports `timeout=` in recent versions. For untrusted input, use `regex` instead of `re`. Fallback: subprocess/thread with hard kill on overrun.

**.NET.** `Regex` has `MatchTimeout` since 4.5; use it. Since .NET 7, `RegexOptions.NonBacktracking` opts into a Thompson-NFA-style engine. Best mitigation story of any default-backtracking ecosystem.

**Node.js / JavaScript.** No native timeout. Spawn the regex in a Worker thread with `worker.terminate()` after a timeout, or use the `re2` npm bindings (linear-time; no backreferences or lookbehinds). For CI: AST-validators that refuse to commit known-bad shapes.

### Worker isolation + CPU budget per request

Architectural defense: every request gets a hard CPU budget. If any path exceeds it, the worker is killed and the request fails. Cloudflare Workers (`cpu-time` limit, default 10ms). Lambda/GCF/Azure Functions (per-invocation runtime limits). Node Workers (main thread enforces setTimeout-based kill). Go (`context.WithTimeout` — cooperative; RE2 doesn't check context but external goroutine kills work). Java application servers (per-request thread budget, Loom virtual-thread cancellation).

### Observability — alert on the tail

Median latency is the wrong signal. Right signals: **p99.9 latency** for any handler running regex on user input (ReDoS adds 100ms-30s; invisible at p99, obvious at p99.9); **CPU-time per request** separate from wall-clock (ReDoS pins a CPU, wall ≈ CPU); **per-worker CPU saturation alerts**; **regex-specific metrics** — histogram match duration, alert when any match exceeds 100ms.

### WAF-layer mitigations

WAFs are the cheapest backstop *as long as the WAF itself isn't ReDoS-vulnerable* (the Cloudflare 2019 irony). Input-size limits (cap headers, bodies, parameter counts — bound the multiplier). Character-class throttling (long runs of one character often trigger nested-quantifier exploits). Known-bad-pattern detection at the input layer. The WAF is a backstop, not a primary defense; primary defense is "don't ship vulnerable regexes" plus "bound compute when they slip through."

---

## 7. Algorithmic Complexity Beyond Regex

### SQL query DoS via user-controlled query shape

When user input influences SQL structure (not just parameters), the database becomes the target. ORMs exposing `where`/`order_by` to API consumers let an attacker pick `order_by` over an unindexed column, forcing a full table scan plus filesort. Full-text-search queries (PostgreSQL `tsquery`, recursive CTEs, lateral joins) cost seconds even on small tables. GROUP BY over attacker-chosen high-cardinality columns produces large intermediate results.

Defense: parameterize **query parameters**, not just **values**. Whitelist allowable `order_by` columns, `group_by` shapes, `where` predicates. Cross-link `code_review_expertise.md`.

### GraphQL query depth/breadth DoS

Nested-resolver model permits arbitrarily-deep nesting by default. Depth `d` with branching factor `N` yields `N^d` resolver invocations. Defenses: max query depth (`graphql-depth-limit`, default 7); max complexity scoring (`graphql-cost-analysis`); persisted queries in production (only allow build-time-registered query hashes); aliased-field count caps (the `{a: foo a2: foo ...}` pattern bypasses depth limits).

### JSON Schema validator complexity

Some validators (Python `jsonschema`, `ajv` in certain configs) have super-linear validation for schemas with `oneOf`/`anyOf`/`not`/`$ref` combinatorics. Attacker-influenced **schema** is the dangerous surface; attacker-influenced **data** validated against trusted schemas is usually linear. Defense: never let users supply schemas; whitelist `format` plugins (some implement `format` via regex — themselves ReDoS-vulnerable).

### YAML alias amplification

```yaml
a: &a [1,1,1,1,1,1,1,1,1,1]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
```

Each alias multiplies content; logarithmic input expands to exponential output. The billion-laughs lineage ported to YAML. Modern parsers (`PyYAML`'s `safe_load`, `js-yaml` v4 default, `yaml.v3` with depth limits) reject or bound this. Custom loaders don't. Cross-link `xml_parser_differential_expertise.md`.

### Cryptographic cost amplification

If `PBKDF2`/`bcrypt`/`scrypt`/`argon2` iteration count is attacker-controlled (per-user field rather than server constant), an attacker creates an account with max iterations and forces per-login crypto cost to seconds or minutes. Same pattern: TLS handshake DH-group size, RSA key size, cert chain depth, OCSP chain depth — anywhere an attacker requests "more work," protocol participation becomes per-request DoS. Cross-link `cryptography_expertise.md`.

### Compute amplification — the general pattern

Three structural conditions for exploitable amplification: (1) input-to-compute ratio is super-linear; (2) no per-request bound; (3) attacker can submit freely. Break any one and the attack is uneconomical. Defense-in-depth means breaking all three.

### Serverless billing as money-DoS

In per-invocation-billed serverless (Lambda, Workers paid, Vercel, Cloud Functions), every algorithmic-DoS converts to billing-DoS. Mitigations: cost-alerts at the billing layer; per-IP rate limits even pre-auth; max invocation time tuned to actual worst-case workload, not platform maximum. Real incidents: Workers users have reported thousands-of-dollars single-day bills from regex DoS via misconfigured `re2`-free regex on user input.

---

## 8. Defensive Patterns

### Input size limits — the first line

**Bound every input before it reaches any parser, matcher, or hash.** Long inputs are the multiplier on which all super-linear complexity bugs depend. HTTP body 1MB-10MB; header lines 8KB total, 256 headers max; query strings 4KB-8KB; form fields 64KB; file-upload chunks bounded per-chunk plus aggregate caps; WebSocket frames bounded with per-connection rate limits. When the framework allows it (Express `body-parser` size limits, Spring `MaxFileSize`), set aggressively. Default "accept up to 100MB" is almost never right.

### Linear-time regex engines — when available

Prefer linear-time engines for untrusted-input regex: Go stdlib `regexp` (RE2, free); Rust `regex` crate (Thompson-NFA); Java `re2j` (Google's Java port); Node `re2` npm bindings (no backreferences/lookbehinds — covers ~90% of production use); .NET 7+ `RegexOptions.NonBacktracking`. Python has no mature RE2 binding — closest is the `regex` module with timeout. Fall back to timeouts when backreferences/lookbehinds are required.

### Regex timeouts — language-native

See Section 6. Set globally where supported (Ruby `Regexp.timeout`, .NET `Regex.MatchTimeout`); wrap per-call otherwise.

### Test regexes against pathological inputs in CI

`vuln-regex-detector` plus CodeQL queries cover most production cases. For high-assurance: per-regex fuzz testing (increasing-length adversarial strings, alert on super-linear runtime); property-based testing; pre-commit hooks refusing known-bad shapes.

### Bound parser depth and content size

Recursive parsers are stack-overflow primitives. Bound: XML (depth, entity-expansion, attribute count, namespace count); JSON (depth — `jackson-databind` defaults 1000; tune down for untrusted); YAML (alias-expansion, depth, document size); HTML (depth, attribute count, PI count — the NekoHtml CVE); custom DSLs (almost always lack bounds by default).

### WAF rules + worker isolation + per-request CPU budget

WAFs (ModSecurity CRS, Cloudflare Managed Rules, AWS WAF) catch body-size, URL-pattern, and pathological-input-shape attacks pre-parse. Backstop, not primary defense.

Every production handler should run with a hard platform-level CPU budget (Workers `cpu-time`, Lambda timeout, K8s pod CPU limits + circuit breakers). Application-level CPU budgets are the fallback.

### Migrate away from backtracking engines

Strategic direction: Go stdlib is RE2; Rust stdlib is Thompson-NFA; .NET 7+ has `NonBacktracking`; Ruby 3.2+ has memoization. Python, Node, Java haven't made the structural move — plan migrations for untrusted-input regex paths.

### Code-review checklist

When reviewing code that includes regex or other complexity-bounded parsing:

1. **Does any regex use nested quantifiers (`(...+)+`, `(...*)*`)?** Reject or atomic-group.
2. **Does any regex use overlapping alternations (`(a|aa)+`, `(\w|\d)+`)?** Restructure.
3. **Does any regex use greedy quantifiers without anchoring?** Anchor (`^...$`) or refuse greedy semantics.
4. **Is the input passed to the regex user-controlled?** If yes, the regex is in scope for ReDoS audit.
5. **Is the input size bounded?** If no, bound it first.
6. **Is there a timeout on the regex match?** Add one.
7. **Is the regex engine linear-time?** If not, document why a backtracking engine is required.
8. **Is the regex constructed dynamically from user input?** Catastrophic — reject and use a parser instead.
9. **Are backreferences or lookbehinds used?** Document the requirement; verify no alternative exists.
10. **Is the regex part of a larger parser chain?** Audit the chain's worst case as a whole.
11. **Does the parser accept user-defined recursion depth?** Bound it.
12. **Does the hash table use a randomized seed?** Verify for any custom or third-party implementation.
13. **Does decompression have an output-size cap?** Add one.
14. **Does the schema/DSL/expression-language accept user-supplied schemas?** Reject — only validate against trusted schemas.
15. **Is there a CPU budget per request?** At the platform level, ideally; at the application level as fallback.

---

## 9. Variant Analysis — Under-Explored

### ReDoS in AI tool outputs

When an LLM generates a regex used to parse other LLM output (common agentic pattern), the regex is in scope for ReDoS. Two failure modes: (1) the LLM generates a vulnerable shape because training corpora are full of them (informal measurements: 5-15% of LLM-generated regexes are polynomial-vulnerable); (2) downstream LLM output is constructed adversarially (by another agent, by prompt-injection) to hit the worst case. Defense: never let an LLM-generated regex run unbounded; wrap in timeout; prefer parsers over regexes when structure is known. Cross-link `llm_agent_security_expertise.md`.

### ReDoS in regex-based prompt-injection defenses

Recursive irony: prompt-injection defenses that use regex to detect injection patterns can themselves be ReDoS-vulnerable. The attacker DoS's the defense by submitting input that fails the regex slowly. Defense regex must be RE2-style or hardened. **Any security control processing attacker-controlled input is in scope for the same algorithmic-DoS audit as the application itself.**

### Complexity in vector-database similarity search

Cosine-similarity search over high-dim embeddings has known worst-cases: queries in low-density index regions force fallback to linear scan; queries matching many entries equally force tie-breaking traversal. Pinecone, Weaviate, Milvus all have surfaces that haven't received the scrutiny traditional DBs have. Defense: bound per-query result count and CPU; rate-limit per IP.

### Markdown-rendering DoS

`cmark-gfm` and `markdown-it` have hardened. Derivative parsers in SSGs, comment systems, doc tools frequently haven't. Combinations of fenced blocks, blockquotes, emphasis, and tables trigger super-linear rendering in many. Audit your Markdown stack; use hardened libraries; bound document size at the input layer.

### WebSocket handshake parsing ReDoS

The WS handshake is HTTP-style header parsing. CVEs in `ws` npm and `websockets` Python (older versions) involve parser state-machine DoS via crafted headers. Pre-auth; attack budget is "open a TCP connection." Position-of-trust amplification.

### Log-parsing ReDoS

The Cloudflare 2019 incident is in this class — a WAF rule processing every request is structurally a log-parser on an unbounded stream. Logstash filters, Fluentd plugins, Splunk extractions, custom log pipelines all run regex on every line; a single vulnerable regex applied per-line produces ingest-pipeline-wide DoS. Audit log pipelines as carefully as request pipelines.

### CI/CD pipeline ReDoS

GitHub Actions expressions, GitLab CI rules, Jenkins pipeline scripts evaluate regex over per-build context. A vulnerable regex applied to user-controlled commit messages, branch names, or PR bodies converts CI minutes into a budget-DoS. Cross-link `cicd_supply_chain_expertise.md`.

### Static-analysis-tool ReDoS

Recursive case: SAST tools that use regex to detect ReDoS in target code are in scope themselves. Semgrep, CodeQL, ESLint plugins all process attacker-influenced source code; a crafted source file that hits the SAST tool's own regex worst case DoS's the build. Audit your SAST tools' regex usage; budget CPU per file.

### LLM-prompt-template ReDoS

When LLM agents construct prompt templates dynamically (regex-driven substitution/stripping) and template input is attacker-controlled (user chat message), template processing is in scope. Often unbounded — measure it. Cross-link `llm_agent_security_expertise.md`.

---

## 10. References

### Foundational papers
- Crosby, S. A. & Wallach, D. S. "Denial of Service via Algorithmic Complexity Attacks." 12th USENIX Security Symposium, 2003. https://www.usenix.org/legacy/events/sec03/tech/full_papers/crosby/crosby.pdf
- Cox, R. "Regular Expression Matching Can Be Simple And Fast (but is slow in Java, Perl, PHP, Python, Ruby, ...)" swtch.com, 2007. https://swtch.com/~rsc/regexp/regexp1.html
- Cox, R. "Regular Expression Matching: the Virtual Machine Approach." 2009. https://swtch.com/~rsc/regexp/regexp2.html
- Cox, R. "Regular Expression Matching in the Wild." 2010. https://swtch.com/~rsc/regexp/regexp3.html

### Modern measurement and detection
- Davis, J. C., Coghlan, C. A., Servant, F. & Lee, D. "The Impact of Regular Expression Denial of Service (ReDoS) in Practice: An Empirical Study at the Ecosystem Scale." ESEC/FSE 2018. https://davisjam.github.io/files/publications/DavisCoghlanServantLee-EcosystemREDOS-ESECFSE18.pdf
- Staicu, C.-A. & Pradel, M. "Freezing the Web: A Study of ReDoS Vulnerabilities in JavaScript-based Web Servers." USENIX Security 2018. https://www.usenix.org/conference/usenixsecurity18/presentation/staicu
- Weideman, N. H. "Static analysis of regular expressions." MSc thesis, University of Stellenbosch, 2017. https://oatd.org/oatd/record?record=handle:10019.1/102879
- Weideman, N., van der Merwe, B., Berglund, M. & Watson, B. "Analyzing Matching Time Behavior of Backtracking Regular Expression Matchers by Using Ambiguity of NFA." CIAA 2016.
- Li, Y., et al. "ReDoSHunter: A Combined Static and Dynamic Approach for Detecting ReDoS." USENIX Security 2021. https://www.usenix.org/system/files/sec21-li-yeting.pdf
- Li, Y., et al. "RegexScalpel: Regular Expression Denial of Service (ReDoS) Defense by Localize-and-Fix." USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/li-yeting

### Hash flooding
- Klink, A. & Wälde, J. "Efficient Denial of Service Attacks on Web Application Platforms." 28C3, December 2011. https://fahrplan.events.ccc.de/congress/2011/Fahrplan/attachments/2007_28C3_Effective_DoS_on_web_application_platforms.pdf
- CVE-2011-4885 (PHP HashDoS). https://nvd.nist.gov/vuln/detail/CVE-2011-4885
- Python PEP 456 — Secure and interchangeable hash algorithm. https://peps.python.org/pep-0456/
- JEP 180: Handle Frequent HashMap Collisions with Balanced Trees. https://openjdk.org/jeps/180
- NCC Group. "Technical Advisory – Hash Denial-of-Service Attack in Multiple QUIC Implementations." 2023. https://www.nccgroup.com/research/technical-advisory-hash-denial-of-service-attack-in-multiple-quic-implementations/

### Public incidents
- Graham-Cumming, J. "Details of the Cloudflare outage on July 2, 2019." Cloudflare Blog. https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/

### Tooling
- Davis, J. `vuln-regex-detector`. https://github.com/davisjam/vuln-regex-detector
- Weideman, N. `RegexStaticAnalysis`. https://github.com/NicolaasWeideman/RegexStaticAnalysis
- Google. RE2 — fast, safe, thread-friendly regex engine. https://github.com/google/re2
- Google. RE2/J — RE2 for Java. https://github.com/google/re2j
- Cloudflare. `re2` Node.js bindings. https://github.com/uhop/node-re2

### Per-language regex documentation
- Ruby 3.2 release notes (Regexp.timeout). https://www.ruby-lang.org/en/news/2022/12/25/ruby-3-2-0-released/
- .NET `Regex.MatchTimeout`. https://learn.microsoft.com/en-us/dotnet/api/system.text.regularexpressions.regex.matchtimeout
- .NET 7 `RegexOptions.NonBacktracking`. https://devblogs.microsoft.com/dotnet/regular-expression-improvements-in-dotnet-7/
- Python `regex` module on PyPI (timeout support). https://pypi.org/project/regex/
- OpenJDK enhancement requests: JDK-8268854 (Simple ReDoS prevention), JDK-8234713 (InterruptibleMatcher).

### Kurt Boberg CVE corpus
- CVE-2018-3739 `https-proxy-agent`. https://github.com/advisories/GHSA-8g7p-74h8-hg48
- GHSA-7wwv-vh3v-89cq `highlight.js` multi-grammar ReDoS. https://github.com/advisories/GHSA-7wwv-vh3v-89cq
- CVE-2022-29546 NekoHtml. https://github.com/advisories/GHSA-6jmm-mp6w-4rrg
- CVE-2022-33082 Open Policy Agent. https://github.com/advisories/GHSA-2m4x-4q9j-w97g
- CVE-2022-26924 Microsoft YARP. https://github.com/microsoft/reverse-proxy/security/advisories/GHSA-8xc6-g8xw-h2c4
- CVE-2022-40151 XStream / GHSA-3mq5-fq9h-gj7j. https://x-stream.github.io/CVE-2022-40151.html

### Standards and surveys
- OWASP. "Regular expression Denial of Service - ReDoS." https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- Snyk Research. "Regular Expression Denial of Service (ReDoS) and Catastrophic Backtracking." https://snyk.io/blog/redos-and-catastrophic-backtracking/
- Davis, J. C. "SoK: A Literature and Engineering Review of Regular Expression Denial of Service (ReDoS)." https://davisjam.medium.com/sok-a-literature-and-engineering-review-of-regular-expression-denial-of-service-redos-e6b10ef547c7

### Cross-references within ~/ai/expertise
- `xml_parser_differential_expertise.md` — XML-parser DoS taxonomy (XXE, billion laughs, entity expansion).
- `deserialization_expertise.md` — XStream and broader Java-deserialization context.
- `code_review_expertise.md` — algorithmic-complexity-aware code review heuristics.
- `semgrep_rule_authoring.md` — rule patterns for ReDoS detection in CI.
- `vulnerability_research_methodology_expertise.md` — scaled-corpus discovery patterns (Davis-style).
- `llm_agent_security_expertise.md` — LLM-generated regex and prompt-injection-defense ReDoS variants.
- `cicd_supply_chain_expertise.md` — CI/CD pipeline ReDoS (GitHub Actions, GitLab CI).
- `cryptography_expertise.md` — cryptographic-cost amplification (PBKDF2, bcrypt iteration parameters).
