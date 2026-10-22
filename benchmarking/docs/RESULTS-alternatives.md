# Three alternative forms of the security-research corpus: results

Pre-registered in `PREREG-alternatives.md` (with the 2026-10-13 addendum written after Reviewer 2 and
before any result was read). 1,450 run records, 725 per model, all status `success`. Eval spend
$124.49 list-price equivalent (Sonnet $96.88, Haiku $27.61). Models: `sonnet` and `haiku` aliases
(claude-sonnet-5-5 and claude-haiku-5-5 on 2026-10-12). Fresh vanilla A and a length-matched placebo P
were run in the same session as K1, K2 and K3.

## Verdicts

| Alternative | Mechanism | Verdict |
|---|---|---|
| K1 Checklist (802 words in the prompt) | cognitive load, checklists | DISCARD |
| K2 Contrast cases (28 vulnerable/fixed pairs, read on demand) | analogical encoding, worked examples | DISCARD |
| K3 Systematic search protocol (959 words in the prompt) | anti premature closure, systematic review | DISCARD |

DISCARD means "not shown at this power" (17 CVE repos, 37 synthetic repos), not "not useful". No
alternative passed the primary recall test on either model: the best Holm-relevant sign p was 0.25.
Zero of the 6 primary tests passed, against 0.3 expected by chance at p = 0.05.

## Primary test: pooled recall K minus A, repo is the unit (54 repos)

Differences below are written K minus A (the tool prints A minus K; signs flipped here).

| | Sonnet K-A [95% CI] sign p | Haiku K-A [95% CI] sign p |
|---|---|---|
| K1 | -0.010 [-0.031, 0.000] 1.00 | -0.058 [-0.146, +0.020] 0.51 |
| K2 | +0.031 [0.000, +0.071] 0.25 | -0.041 [-0.122, +0.041] 0.51 |
| K3 | +0.031 [-0.010, +0.092] 0.62 | -0.061 [-0.143, +0.010] 0.45 |
| P (placebo) | 0.000 [0.000, 0.000] 1.00 | 0.000 [-0.061, +0.061] 1.00 |

Rule outcomes (PREREG addendum):

- Primary (CI above 0 and Holm p below 0.05): K1, K2, K3 fail on both models.
- Harm floor (pooled K-A no worse than -0.05): K1 (-0.058) and K3 (-0.061) fail on Haiku. K2 is
  inside the floor (-0.041). No CI excludes 0 on the negative side.
- Beats the placebo: on Haiku all three are below P (K1 -0.058, K2 -0.041, K3 -0.061 versus P). On
  Sonnet K2 and K3 sit +0.031 above P, K1 sits -0.010 below. Neither is significant.
- K2 delivery check: guide files were opened in 100% of K2 runs on both models. K2's null is not a
  delivery failure.
- Truncation: every run in every arm finished with status `success`, so no arm is flagged.

## By suite

Real CVEs (17 repos, 2 reps), recall, K minus A:

| | Sonnet | Haiku |
|---|---|---|
| K1 | -0.029 [-0.088, 0.000] p 1.00 | -0.147 [-0.382, +0.059] p 0.73 |
| K2 | +0.088 [0.000, +0.176] p 0.25 | -0.118 [-0.353, +0.118] p 0.51 |
| K3 | +0.088 [-0.059, +0.235] p 0.62 | -0.176 [-0.412, +0.029] p 0.45 |

- CVE is the cleaner test (the K1 and K2 designs name shapes that overlap the synthetic suites'
  taxonomy, per Reviewer 2). The only positive signal anywhere is K2 on Sonnet, +0.088, which is
  the same size as the old existing-corpus result (A vs C, 0.059, p 0.50), CI touching 0.
- Synthetic suites (wide, mixup, ssrf, 37 repos): Sonnet recall is identical across all arms (at the
  ceiling, zero difference). Haiku differs by at most 0.010. These suites cannot show a recall gain.

## Volume and cost (findings per run, mean $ per run)

| suite, model | A | K1 | K2 | K3 | P |
|---|---|---|---|---|---|
| CVE, Sonnet | 1.18 | 0.65 | 1.12 | 0.71 | 1.09 |
| CVE, Haiku | 5.76 | 2.79 | 4.32 | 2.65 | 6.47 |
| wide, Haiku | 2.41 | 1.33 | 1.59 | 1.33 | 2.41 |

K1 and K3 roughly halve findings per run on CVE. K3 costs more on Haiku CVE ($0.106 per run versus
$0.066) and about 12% more on Sonnet CVE. The placebo costs more than vanilla on Haiku CVE ($0.259
versus $0.066), so prepended prose alone can raise cost without raising recall. Recall did not
track volume in the direction K3 predicted: fewer findings and lower Haiku recall, not more.

## Precision (exploratory, not in the pre-registered verdict rule)

False positives per run on the synthetic suites, A minus K (positive means the alternative has fewer):

| | Sonnet raw | Haiku raw | Haiku +G |
|---|---|---|---|
| K1 | +0.000 [-0.090, +0.099] | +0.396 [+0.180, +0.667] | +0.392 [+0.127, +0.667] |
| K2 | -0.009 [-0.072, +0.054] | +0.297 [+0.171, +0.450] | +0.185 [+0.056, +0.336] |
| K3 | +0.081 [+0.009, +0.171] | +0.441 [+0.234, +0.712] | +0.429 [+0.210, +0.673] |
| P | -0.045 [-0.099, -0.009] | +0.054 [-0.090, +0.216] | -0.333 [-0.617, -0.086] |

On Haiku all three alternatives cut false positives at fixed recall on the synthetic suites, and the
gain survives the verifier gate (+G). The placebo does not, so this is content, not prompt length.
The likely mechanism is the "do not report" blocks in K1 and K3 and the decoy cases in K2, which the
pre-registered rule treated as a recall confound (Reviewer 2). The arm that would isolate it, a K1
do-not-report-only note, was not run. Because this analysis was chosen after the results were seen,
treat it as a lead, not a finding. The synthetic false-positive labels are the author's.

## Limits

17 CVE repos and 2 reps: low power, sign tests have few non-tied repos. Haiku CVE recall is volume
confounded, and K1 and K3 cut volume. No precision measure on the CVE suite. Authors and subject
share a model family. A K1 do-not-report-only arm and an inline K2 (cases pasted into the prompt)
were not run, so form is not separated from delivery channel for K2. Old guides runs (arm C) are a
cross-session reference, not a concurrent control. The harness code gained an in-prompt notes arm
and a `--label` option for this study; two Guardian Shadow notes on them (the notes wrapper is not in
`config_id`; a label can rename a non-N arm) were left unfixed except the multi-arm label check.

## Recommendation

Do not replace or supplement the existing corpus with any of K1, K2 or K3 on the strength of recall:
none beat vanilla, and on Haiku K1 and K3 trend lower. If a follow-up is worth its cost, test the
precision lead directly: a do-not-report-only note against K1 and K3 on a suite with complete gold,
registered before the runs.
