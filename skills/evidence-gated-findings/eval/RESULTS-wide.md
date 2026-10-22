# Results: wider bug classes (injection, authorization, logic, authorizer mix-ups)

Date: 2026-10-12. Model `sonnet`, generator and verifier. Pre-registered in `PREREG-wide.md`
(including the addendum, which was written after the wide run and before the mixup run).

## Verdict: gate stays REJECTED as default, now with less upside than on SSRF

Pre-registered rule: pooled precision gain of at least 15 points B to B+gate with under
10 points of recall loss, and no more than 1 lost true positive on the mix-up class.

| suite | repos | runs/arm | B precision | B+gate precision | gain | recall B to B+gate | cost/run B to B+gate |
|---|---|---|---|---|---|---|---|
| ssrf (earlier) | 13 | 39 | 0.80 | 0.92 | +11.2 | 1.00 to 1.00 | $0.070 to $0.105 |
| wide | 17 | 51 | 0.88 | 0.92 | +4 | 1.00 to 0.96 | $0.056 to $0.093 |
| mixup | 7 | 21 | 0.71 | 0.85 | +14 | 1.00 to 0.94 | $0.055 to $0.113 |

Only the SSRF and mixup gains approach the bar, and neither reaches it. The mix-up
condition passed (0 of 15 mix-up true positives lost on wide; 1 of 18 on mixup).
TP counts include duplicate findings on the same sink; recall is per run and capped at 1.

## What the numbers say

- **The closely-named authorizer mix-up is not hard for this model.** Vanilla and
  skills-equipped Sonnet found every seeded instance: bool check called where the
  throwing variant was meant, swallowed exception, missing `await` on an async
  authorizer, an import alias that turns `is_allowed` into `require_allowed`, an
  ignored Go error, a misleadingly named `requireRole` that returns a bool, and a
  near-identical decorator pair. 33 of 33 across both suites, with no false positives on
  the correctly used siblings. A ceiling, so this class cannot show a gate benefit.
- **The current skill suite adds little.** Precision B vs A: 0.88 vs 0.85 (wide), 0.71 vs
  0.66 (mixup), for 30 to 45 percent more cost per run.
- **Where the gate loses true positives, mostly it is context starvation.** Of the
  `UNVERIFIABLE` verdicts on true bugs, nearly all say a caller, `g.user` setter or
  context value is not in the snippet. That is a defect of small synthetic repos and
  probably less common on real ones, but real repos also hide middleware outside the
  scanned directory. The gate's defensible failure mode is "I cannot see the caller".
- **Logic bugs lose most** (14 to 10 TP findings on wide, B): reachability depends on
  code outside the file.

## Labels are contaminated by bugs I did not intend (disclosed, not corrected)

Several "false positives" are real issues in my own corpus: client-trusted identity header
in `mx-py-alias` and `mx-py-clean`, whole-body mass assignment on a PUT in `mx-js-await`,
cross-tenant role scope in `mx-java-misnamed`, an unauthenticated `org` parameter in the
"clean" `cl-js-inj`, non-expiring reset tokens in `lg-php-token`, a NaN quantity in
`lg-node-price`. Precision is therefore understated for every arm. Not relabelled here
(post hoc relabelling favours the change under test). Next version of the corpus should
be audited before use: run a vanilla agent several times, adjudicate every non-gold
finding once, and fix or exclude those repos before any comparison.

## Limits

Synthetic repos written by the author of the rubric; same-family verifier; 3 correlated
reps per repo; no confidence intervals; one model; the mixup suite is exploratory and
ceilinged. The guard rule "UNVERIFIABLE is not reported" is a policy choice; counting it as
reported would restore recall at the cost of most of the precision gain.

## Reproduce

    uv run python eval/run_eval.py --suite wide  --skills-dir <dir with security-research/>
    uv run python eval/run_eval.py --suite mixup --skills-dir <dir with security-research/>
    uv run python eval/score.py --suite wide --by-class
