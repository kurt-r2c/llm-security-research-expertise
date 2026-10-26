---
name: root-cause-fanout
description: Decompose a CVE, advisory or crash reported against a product, runtime or framework down to the single-purpose library or function that actually breaks its contract, then fan out to every other consumer and every other implementation of that component. Use when triaging a new CVE, deciding blast radius, or asked "who else is affected"; especially when the root cause sits in a codec, parser, decoder or reference implementation.
allowed-tools: Read, Grep, Glob, Bash, WebSearch, WebFetch
---

# Root-cause fan-out

A CVE is filed against whoever shipped it, not whoever wrote the bug. "Node.js
Brotli RCE" is a defect in Google's Brotli decoder that Node happens to embed.
Explaining how the Node path triggers it answers the least useful question.
The useful questions are below the product and to the side of it: what single
component broke, who else ships that component, who else implements the same
thing, and what else the same defect does.

Work in four passes. Do not start a pass until the previous one has its
evidence written down. Use `report-template.md` for the output.

## 1. Descend to bedrock

Bedrock is the most specific component whose own job is the thing that went
wrong: a decoder, parser, codec, allocator, regex engine, certificate verifier.
You are at bedrock when you can write all of:

- **Component and function**: `library@version`, `file:function`.
- **Violated invariant**: the contract it broke, in one line ("return value of
  `X` unchecked, so the output cursor passes the end of the ring buffer").
- **Affected and fixed ranges** of the component itself, not of the product.
- **Where the fix landed**: the commit in the component's own repo. If the
  product's fix is a vendored-directory update or a dependency bump, that is
  the signal you have not reached bedrock yet. Keep descending.

How to descend:

1. Read the product's fix diff before its advisory text. Paths like
   `deps/`, `third_party/`, `vendor/`, `external/` or a lockfile bump point
   down a level.
2. Ask of each component: is the failing operation this component's purpose?
   If a web runtime overflows while decompressing, decompression is not the
   runtime's purpose. Go to the decompressor.
3. Record the **amplifiers** separately: what the product did that made the
   defect reachable or worse (decodes attacker input by default, no error
   handler, runs privileged, no size cap). Amplifiers set severity per
   consumer. They do not drive the fan-out.
4. Confirm the advisory is the one you think it is. Branded names
   ("X2Shell") get coined by media and reused; two unrelated CVEs in the same
   week get merged in retellings. Match CVE ID, CWE and fixed version against
   the component's own advisory or commit.

If bedrock is genuinely the product's own logic, say so, and skip to pass 4
for that product alone. Not every CVE has a library underneath.

## 2. Fan out to consumers

Consumers inherit the component by different mechanisms. Each one needs a
different search, and each gets fixed on a different schedule. Cover all four
and say which you did not check.

| Mechanism | Example shape | Gets the fix when | How to find them |
|---|---|---|---|
| Dynamic link to a system library | distro `libfoo.so` | the OS package updates | distro reverse deps (`apt-cache rdepends`, `dnf repoquery --whatrequires`, `brew uses --installed`), Repology |
| Vendored or bundled source | `third_party/foo/` compiled in | each consumer cuts a release | code search for the component's unique file names, symbols, version macros or error strings. SBOMs and package managers usually miss these |
| Binding package that bundles its own copy | PyPI wheel, crate `-sys`, npm native addon, PECL ext, JNI natives jar | the binding re-vendors and releases | registry reverse dependencies, then read each binding's build to see whether it links the system copy or its own |
| Embedded in a runtime | browser, JS runtime, managed runtime | the runtime ships | runtime release notes, then everything built on that runtime |

Then go one hop further: which applications expose the runtime's or
binding's capability to untrusted input. Advisory "affected products" lists
and vendor blog posts are a lower bound. Expect the list to grow for days
after disclosure.

## 3. Fan out to other implementations

If bedrock is a reference implementation, or the spec has few
implementations, each one is a candidate for the same defect.

- **Ports and transliterations** of the reference (machine-translated or
  hand-ported to another language) often inherit its logic, including its
  mistakes. A memory-safe port turns an out-of-bounds write into a panic, an
  exception or silent truncation: still a finding, usually DoS.
- **Independent implementations** of the same spec: read the spec clause the
  bug violates. If the spec is ambiguous there, the root cause may be the
  spec, and several implementations will disagree.
- **Run the trigger input through every implementation you can.** Differences
  in what they accept or emit are findings on their own (parser differentials
  feed smuggling, cache poisoning and filter bypass).

## 4. Enumerate side effects and reach

The headline consequence (RCE, OOB write) is one effect of one input. For
each consumer, record:

- **What malformed or hostile input does**: memory corruption, abort,
  unhandled exception that ends the process, catchable error, partial output
  accepted silently, resource amplification (decompression bombs,
  pathological backtracking).
- **Which direction attacker data enters**: inbound request, fetched
  response (clients, crawlers, proxies, SSRF targets), uploaded or opened
  files, IPC. Do not assume the obvious direction. "HTTP supports Brotli
  request compression" does not mean servers decode it by default; most do
  not, while HTTP clients decode Brotli responses everywhere.
- **Default or opt-in**, with the config switch or build flag that gates it.

## Done when

- The bedrock card is complete, with sources.
- Every consumer mechanism in pass 2 was searched, or is listed as not checked.
- Every known implementation in pass 3 has a status: affected, not affected
  (with evidence), or unchecked.
- Side effects and reach are recorded per consumer, default versus opt-in.
- Every claim carries a source or `[unverified]`.

Stopping at bedrock is the common failure: bedrock is where the fan-out
starts. Spending the effort on the product-specific exploit path before
bedrock is established is the other one.

## Limits

- Code search finds vendored copies by matching strings. Renamed, minified or
  stripped copies need symbol or binary matching, which this skill doesn't do.
- Version strings lie. A consumer can vendor the fixed version number with the
  patch reverted, or backport the patch without bumping the number. Check the
  patched line where it matters.
- Reach and default-config claims age fast. Date them.

See `references/brotli-worked-example.md` for the pattern applied to a real
case.
