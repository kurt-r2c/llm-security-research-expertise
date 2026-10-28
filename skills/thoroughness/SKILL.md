---
name: thoroughness
description: Before calling any enumeration, audit, survey, matrix, or "complete" list done, interrogate its completeness with a five-whys descent so you stop enumerating by familiarity and start enumerating by mechanism. Use whenever the task says "every / all / full list / across X", whenever the answer's value depends on not missing cases, or whenever you are about to write "the main ones are…". Especially when a human has had to re-steer you toward completeness even once.
allowed-tools: Read, Grep, Glob, Bash, WebSearch, WebFetch
---

# Thoroughness — five-whys for completeness

The classic Five Whys chases a failure down to its root cause. This runs the same
descent on a *list*: keep asking **"why is this list complete?"** until the answer is a
mechanism, not your memory. The failure mode this prevents: you enumerate the items you
can readily name (the popular, the installed, the English-named, the ones already in
context), declare the set, and stop — and a human has to say "you forgot X."

If a human has re-steered you toward completeness even once on this task, you are already
in the failure mode. Stop adding items one at a time as they get named. Fix the **axis**.

## Projects lie

A project's docs, README, config names, changelog, version string, and capability claims
are marketing and intent, not behavior. A decompression option was documented
"client-side"; the server decoded `br` anyway. A fix "landed in 1.2.1"; a vendored copy had reverted it.
A framework "doesn't support brotli"; its Netty decompressor did. A guard "exists in every
version"; only the return value changed.

Treat every self-description as a **hypothesis**, and settle it against ground truth: send
the input and watch what comes back, or read the one line that actually does the work.
The verdict comes from behavior you observed, never from a claim you read.

> "The docs say it decodes client-side only" is not a finding.
> "I sent a brotli body and the server returned the decoded length" is.

When you cannot run it, say so and fall back to reading the code that implements the claim
— not to repeating the claim. "Code-verified" cites a line; "the README says" cites nothing.

## The descent (run it out loud, in the artifact)

Ask "why is this list complete?" and attack each answer:

1. **Why these items?** If the honest answer is "they're the ones I know / the popular
   ones / the ones already installed / the ones in the prompt" — that is the red flag.
   Familiarity is not a boundary. Keep going.
2. **What is the real axis?** Enumerate by the shared *mechanism, cause, or contract*,
   not by instances. "Frameworks I can name that decode brotli" is a memory axis;
   "everything that links the brotli decoder" is a mechanism axis — and it has a
   findable, countable membership (reverse-dependencies, code search, a spec's
   implementers). Re-derive the list from the mechanism.
3. **What else shares the mechanism?** Walk every fan-out dimension and name what is in
   each, or that it is empty:
   - other **implementations** of the same spec (ports, reimplementations, clones);
   - other **consumers** of the same component (reverse deps, bindings, vendored copies);
   - other **languages / runtimes** that expose the same capability;
   - **upstream** dependencies and **downstream** dependents (one hop each way);
   - the substrate: **transports, bindings, ports, FFI** under the named instances;
   - the **long tail**: commercial, deprecated/EOL, niche, non-English, not-on-your-OS.
4. **What did I exclude, and does the exclusion have a reason?** Every branch you do not
   cover gets a one-line reason: *out of scope* (with the scope rule), *verified absent*
   (with the evidence), or *not reachable here* (toolchain/data unavailable — say which).
   A silent omission is the defect. An explicit exclusion is thoroughness.
5. **Ask again until it is empty.** Re-ask "what in this category have I not named?"
   Only stop when **two consecutive rounds surface nothing new** — not when you run out
   of the ones you remembered.

## Done when

- The enumeration axis is a **mechanism**, and you can say how its membership is bounded
  (reverse-deps / code search / the spec's implementer list / a registry), not "these
  are the main ones."
- Every branch is **covered or explicitly excluded with a reason**.
- You asked "what am I missing?" until it returned nothing twice.
- You can answer **"how do I know this is exhaustive?"** with a method, not a vibe.

## Anti-patterns (each means: go back to step 2)

- "The main ones are…", "the popular…", "…and others", "etc.", trailing off.
- Listing only what is installed, easy to build, or already in context.
- Treating popularity, recency, or your training familiarity as the edge of the set.
- Reporting the covered items but not the ones you skipped and why.
- Waiting for the human to name the thing you missed.

## Relation to other skills

This is the general discipline. `root-cause-fanout` is its specific application to a CVE
or crash: descend to bedrock, then fan out to every consumer and implementation. When the
subject is a defect in a component, use that skill; the descent here is the same move.
