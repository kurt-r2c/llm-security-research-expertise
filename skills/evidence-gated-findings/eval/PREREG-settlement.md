# Settlement tests: decision criteria (written 2026-10-12, before arm D and the final pairwise)

Disclosure: A/B/C CVE-suite counts and the skill-invocation traces had been seen when this
was written. Arm D (skills forced) and all pairwise statistics had not.

Arms: A vanilla; B skills listed (found to never trigger, so effectively A plus listing
overhead); C vanilla plus `expertise/` guides (read in nearly every run); D skills forced
via an explicit instruction; +G gate (general verifier); +F gate with a maintainer facts note.

An arm X is "necessary" versus Y only if, on matched (repo, rep) runs:
- recall difference X minus Y has a bootstrap 95% CI excluding 0 on the pooled synthetic
  suites for that model, OR on the CVE suite a sign-test p under 0.05; AND
- precision does not drop by more than 5 points (synthetic suites).
Otherwise "not shown necessary". Cost is reported, not decisive.

Per-test questions:
1. Corpus: C vs A on the CVE suite (post-cutoff) and on the long-tail synthetic classes.
2. Scaling: does any of B, C, D help Haiku more than Sonnet (compare the effect sizes).
3. Invocation: B's skill-invocation rate (observed 0 percent). If B never triggers, B vs A
   is not a test of the skills; D is.
4. Facts note (stand-in for the context tool): +F vs +G on wide and mixup UNVERIFIABLE rate
   for true bugs and net recall. A code-graph context tool cannot be tested on single-file
   synthetic repos (the missing context is not in the repo); on the CVE suite it would need
   a build step not run here.
5. Corpus audit: done first; adjudicated scoring is the default, `--strict` reproduces the
   original numbers.

CVE-suite caveat: recall is "a finding landed within 5 lines of the fix hunk"; other real
bugs in these repos are unlabelled, so precision is not measured there, and models that emit
many findings get more chances to land a hit. Report findings-per-run next to recall.
