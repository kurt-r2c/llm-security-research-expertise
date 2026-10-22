# Facts note on post-cutoff CVEs (17 repos)

Pre-registered in the "Addendum 2026-10-12" of `PREREG-settlement.md` before any of these runs. Arm E prepends a
generic project description (the repo's public README tagline) plus a generic threat-model note to the generator
prompt. +F is the verifier given the same note. Fix commits and advisories are dated on or after 2026-07-01, the
model cutoff is June 2026. 17 repos, 2 reps, Sonnet and Haiku, read-only tools, Bash denied. Every run record has
status `success` (no budget-exhausted runs).

Decision rule (fixed in advance): E counts as necessary-grade versus A if the repo-level sign p is below 0.05 or the
bootstrap CI over repos excludes 0 on recall.

## Result: the rule fails. The facts note is not shown necessary on real post-cutoff CVEs.

Runs (of 34) with a finding inside 5 lines of a fix hunk, and raw findings per run:

| arm | Sonnet runs hit | Sonnet findings/run | Haiku runs hit | Haiku findings/run |
|---|---|---|---|---|
| A vanilla | 5 | 1.1 | 18 | 6.4 |
| B skills listed (14 runs) | 4 | 1.1 | 8 | 6.2 |
| C guides | 7 | 1.3 | 12 | 5.0 |
| D skills forced | 6 | 1.4 | 15 | 3.9 |
| E facts note | 8 | 1.2 | 15 | 5.6 |

Pairwise recall, X minus Y, repo is the unit (17 repos):

| pair | Sonnet d [95% CI] p | Haiku d [95% CI] p |
|---|---|---|
| A vs E | -0.088 [-0.176, +0.000] 0.25 | +0.088 [-0.118, +0.324] 0.69 |
| A vs C | -0.059 [-0.147, +0.000] 0.50 | +0.176 [+0.000, +0.353] 0.18 |
| A vs D | -0.029 [-0.088, +0.000] 1.00 | +0.088 [-0.088, +0.265] 0.51 |
| C vs E | -0.029 [-0.118, +0.059] 1.00 | -0.088 [-0.353, +0.206] 0.55 |

- Sonnet: E is directionally ahead of A (8 vs 5 runs), but only three repos move (kinopenapi-auth, mariadb-nobs,
  olivetin-api), the CI touches 0 and sign p is 0.25.
- Haiku: E is not ahead of A (15 vs 18 runs, point estimate favours vanilla). Neither guides (C) nor forced skills
  (D) beat vanilla either.
- 11 of 17 repos were missed by every Sonnet arm in every rep. For Haiku, dulwich-stash, fastjwt-jwk,
  gitpython-submodule and pyjwt-algs were missed by all arms. Prompt-side context did not move the hard cases.
- Strawberry (the authorizer-awaitable bug) stays missed by Sonnet in every arm, and Haiku found it in A and E only
  by volume (about 6 findings per run).

## Verifier given the note (+F) versus the general verifier (+G)

Runs hit after filtering (of 34):

| | raw | +G | +F |
|---|---|---|---|
| Sonnet A | 5 | 5 | 5 |
| Sonnet E | 8 | 8 | 8 |
| Haiku A | 18 | 15 | 8 |
| Haiku C | 12 | 12 | 9 |
| Haiku D | 15 | 10 | 7 |
| Haiku E | 15 | 11 | 10 |

- Sonnet: gate and +F change nothing. Sonnet emits about one finding per run and the verifier keeps it.
- Haiku: +F discards real fix-site findings. A vs A+F is +0.294 [+0.118, +0.500], sign p 0.03. A+G vs A+F is
  +0.206 [0.000, +0.441], p 0.29. On real CVEs +F keeps fewer true bugs than +G, the reverse of the synthetic result
  (where for A, +F cut the true bugs the gate could not verify from 7 to 1).
- Precision is not measured on this suite (no complete gold), so what +F removed in false positives is unknown.
  The recall cost is measured; the benefit is not.

## What this does and does not show

- Falsified: that prompt-side knowledge (skills, guides, or a facts note) improves recall on post-cutoff bugs for
  Sonnet or Haiku. None clears the pre-registered bar, and Haiku point estimates are negative for all of them.
- Not falsified: the synthetic-suite result that a facts-fed verifier recovers true bugs the general verifier
  throws away (63 of 63 kept in arms A and B). It did not transfer to real CVEs. The note text for the synthetic
  suites was written after I had seen the gate's context-starvation failures, so that result was tailored.
- Not tested: a code-graph or caller/callee context tool, and a verifier that must produce an executable proof.
  Neither was built.
- The CVE note is deliberately generic (README tagline, no class, no file). A note that names the trust boundary
  would likely score higher, but that is leakage of the answer on this suite, not a fair test.

## Limits

17 repos, 2 reps. Only a handful of repos are ever non-tied in a pair, so the sign test has little power. Recall on Haiku is volume-confounded
(about 6 findings per run against Sonnet's 1). No precision measure. Fix-site match is a 5-line window around the
fix hunk. The "post-cutoff" claim rests on commit and advisory dates, not on a check that the models lack the code.
`config_id` now also hashes the facts note; records made before this change carry the older id, so a rerun of the
CVE suite regenerates rather than reusing them.
