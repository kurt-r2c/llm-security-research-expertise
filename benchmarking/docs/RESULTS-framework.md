# Battle-testing the framework

The framework (`ablate run --arm-cmd`, controls O/H, `verdict`, `power`, `calibrate`, `fixcheck`; guide in
`FRAMEWORK.md`) was exercised end to end on the alternative-corpus study (`RESULTS-alternatives.md`),
then extended to a 51-repo real-CVE suite (the original 17 plus 34 screened post-cutoff advisories,
selected mechanically by `ablate`'s screener with no model results used). Models: `sonnet`, `haiku`
(claude-sonnet-5-5, claude-haiku-5-5 on 2026-10-12). This file reports whether the framework detects what it should,
what it says about the harness arms at 51 repos, and what it cost to learn that.

## 1. Does the framework see a real gain, a real harm and a null? (controls)

| Check | Sonnet | Haiku | Verdict |
|---|---|---|---|
| Positive control O (file named): recall, 51 repos | +0.520 [+0.392, +0.647], p 0.00 | +0.314 [+0.206, +0.431], p 0.00 | detected on both |
| Negative control H (budget 0.02): recall, 17 repos | -0.118 [-0.265, 0.000], p 0.25; 0 of 34 runs finished | -0.353 [-0.500, -0.206], p 0.00; 15% truncated | harm detected on Haiku; on Sonnet only through the truncation check |
| Adapter self-test (raw model through `--arm-cmd`) vs A | -0.029 [-0.088, 0.000], p 1.00 (17 repos) | +0.020 [-0.069, +0.108], p 1.00 (51 repos) | ties A on both |
| A/A false-pass rate (random split of A's reps, 1,000 splits, nominal 0.05) | sign 0.000, CI 0.000, both 0.000 | sign 0.020, CI 0.062, both 0.020 | rule at or below nominal |
| Cross-session drift (old A vs new A, 17 repos) | -0.029 [-0.088, 0.000] | -0.029 [-0.235, +0.206] | about 0.03 |

Lessons:

- The oracle is the check that a null means something: the same rule that rejects K1, K2 and K3 passes O with p 0.00.
- Harm needs headroom. Sonnet's baseline recall is 0.137, so a run that produces nothing barely moves recall. The
  harm floor never fires; the **truncation check** does (100% versus 0%). Keep both.
- Effects under about 0.03 cannot be told from session drift.
- The CI-only rule is slightly liberal on Haiku (0.062 at nominal 0.05); requiring the sign test as well,
  as `verdict` does, brings it to 0.020.

## 2. Power: why 17 repos could not answer the question

`ablate power` on the 51-repo baselines (2 reps; 80% power; rule = CI above 0 and sign p below 0.05):

| | Sonnet | Haiku |
|---|---|---|
| baseline recall | 0.137 | 0.471 |
| repos always missed / always found / informative | 43 / 6 / 2 | 20 / 17 / 14 |
| smallest gain detectable at 17 repos | above 0.20 | above 0.20 |
| at 34 / 51 / 80 / 120 repos | 0.15 / 0.10 / 0.10 / 0.05 | above 0.20 / 0.20 / 0.15 / 0.10 |

Most real bugs in the suite are missed by every arm (Sonnet: 43 of 51 repos), so few repos carry signal. Add
repos, not reps. The 17-repo study could not have detected anything under about 0.20; the 51-repo suite
reaches about 0.10 on Sonnet and about 0.20 on Haiku.

## 3. What the larger suite changed about the K1, K2, K3 verdicts

Pooled recall, candidate minus vanilla (51 CVE repos; Holm over 6 tests):

| | Sonnet | Haiku |
|---|---|---|
| K1 | -0.029 [-0.078, 0.000] p 0.50 | -0.176 [-0.284, -0.078] p 0.01, Holm 0.04 |
| K2 | +0.088 [+0.029, +0.167] p 0.03, Holm 0.15 | -0.108 [-0.216, +0.010] p 0.05, Holm 0.16 |
| K3 | +0.069 [0.000, +0.147] p 0.22, Holm 0.44 | -0.157 [-0.265, -0.049] p 0.03, Holm 0.15 |
| P (placebo) | +0.098 [+0.020, +0.196] p 0.06 | +0.088 [-0.020, +0.196] p 0.24 |

Verdicts stay DISCARD for all three, for sharper reasons: on Haiku all three breach the -0.05 harm floor, and K1 is
significantly worse than vanilla even after Holm over all six tests (Holm 0.04); `verdict` now says so explicitly. K2 on Sonnet is the one nominal gain (CI above 0,
raw p 0.03), but it does not survive Holm and sits at the placebo (K2 minus P = -0.010).

**The placebo finding.** The placebo note, written to be "content-free", lifts Sonnet recall by +0.098
over vanilla (51 repos). It tells the model to be systematic, cover the whole repository and
look again at skipped files, which is an effort instruction, not neutral padding. So K2's gain, and K3's,
is no larger than a generic thoroughness nudge. For anyone auditing a harness, two consequences: use a
placebo that carries no instructions (for example a long neutral description of the repository
conventions), and treat "be thorough" as a cheap baseline arm your harness must beat. The placebo comparison in
the rule caught this; without it K2 would have been read as a success.

### Volume-matched view (`ablate volmatch`): the Haiku losses are volume suppression, not worse judgement

Recall rises with findings per run. Comparing each arm with the baseline downsampled to that arm's volume:

| arm | model | recall | baseline at the arm's volume | arm minus matched baseline |
|---|---|---|---|---|
| K1 | Haiku (51) | 0.294 | 0.233 | +0.061 [-0.035, +0.155] |
| K2 | Haiku (51) | 0.363 | 0.321 | +0.042 [-0.051, +0.140] |
| K3 | Haiku (51) | 0.314 | 0.245 | +0.069 [-0.010, +0.150] |
| K2 | Sonnet (51) | 0.225 | 0.140 | +0.086 [+0.025, +0.167], p 0.02 |
| K3 | Sonnet (51) | 0.206 | 0.130 | +0.076 [+0.018, +0.153], p 0.12 |
| P (placebo) | Sonnet (51) | 0.235 | 0.111 | +0.125 [+0.043, +0.221], p 0.04 |

The added text makes Haiku report fewer findings (5.5 down to 2.4 to 3.5 per run), and the recall it loses is what
a thinner sample of vanilla's own findings would lose; per finding the arms are no worse, if anything slightly
better, with intervals that include 0. On Sonnet K2, K3 and the effort-prompt placebo all rank better per finding
than vanilla, and the placebo most of all, so the content of K2 and K3 is not what helps. A harness verdict should
quote both recall and this matched number.

## 4. Precision proxy on real CVEs (`fixcheck`, Haiku, 51 repos)

| arm | pre-fix hit | fix-tree alarm | discrimination (hit minus alarm) |
|---|---|---|---|
| A | 0.471 | 0.206 | 0.265 |
| K2 | 0.363 | 0.157 | 0.206 |
| K3 | 0.314 | 0.108 | 0.206 |

K2 and K3 lower both the hit rate and the false-alarm rate; the difference in discrimination is not
significant (K2 -0.059, K3 -0.059, CIs include 0). On Sonnet (17 repos) alarms are too rare to say anything.
This is consistent with the synthetic-suite lead in `RESULTS-alternatives.md`: the added text works as a
volume brake, not as better judgement. Caveat: a finding near the new guard code on the fix tree counts
as an alarm, so the proxy over-counts slightly for every arm equally.

## 5. Volume and cost (CVE suite, findings per run)

| | A | K1 | K2 | K3 | P | O |
|---|---|---|---|---|---|---|
| Sonnet | 1.04 | 0.57 | 1.12 | 0.69 | 1.04 | 1.46 |
| Haiku | 5.47 | 2.38 | 3.54 | 2.50 | 6.10 | 3.73 |

Cost per run on Haiku CVE: A $0.077, K2 $0.052, K3 $0.102, P $0.240. A harness that adds text can make the
raw model slower and more expensive without finding more.

## 6. Self-test on the fixed code (`ablate selftest`, Haiku, 2 reps)

Run after the review fixes (cache key, label lock, notes hash, scratch cleanup), through the shipped command. The
first run used only the 17 original repos; the second, now the command's default, uses every repo in the suite (51).

| check | 17 repos | 51 repos |
|---|---|---|
| oracle gain visible | FAIL: +0.235 [0.000, +0.471] | PASS: +0.284 [+0.147, +0.422] |
| adapter ties baseline | PASS: +0.059 [-0.118, +0.235] | PASS: -0.010 [-0.118, +0.098] |
| handicap harm visible | PASS: -0.265 [-0.471, -0.029]; truncation 0.21 vs 0.00 | PASS: -0.333 [-0.451, -0.216]; truncation 0.10 vs 0.00 |
| A/A false pass rate <= 10% | PASS: 0.014 | PASS: 0.013 (CI-only 0.054) |
| smallest detectable gain at 80% | above 0.30 | 0.20 |

The 17-repo failure is the self-test doing its job: the oracle's lower bound lands at exactly 0.000 and the power line
says the suite cannot see gains under 0.30, so a verdict from that configuration should not be trusted. The command now
prints that hint, and defaults to the full suite, where all four checks pass. A self-test that only ever passed would be
a poor test; this one flagged an underpowered setup correctly and cleared the larger one.

## 7. Fresh-eyes dry run (a stand-in for an outside user)

A subagent with no context followed `README.md` and `FRAMEWORK.md` in a clean copy of the repository: `uv sync` and
the tests (46 passed), the self-test on 4 repos, a harness adapter written from the docs alone, and `ablate verdict`.
Its verdict on the pre-fix docs: **yes, with help.** Commands did what the docs said and the self-test explained its own
failure (4 repos cannot show the oracle), but it got stuck at:

| friction | fix |
|---|---|
| `verdict` crashed with `KeyError: 'P'` on the example rule when no placebo arm had been run | readable error naming the arm and the `"placebo": null` option; missing baseline or candidate arms also named |
| arms with unequal repo coverage were compared silently on the intersection | warning with the repo counts per arm |
| `mode`, the floors' units, `delivery` and the output columns were undefined | "Rule file reference" table in `FRAMEWORK.md`; `_`-prefixed keys ignored so rules can be annotated |
| no minimal recipe; run-directory and shell-quoting rules unstated | "Minimal first audit" with the exact commands |
| no path to the 50+ repos a real verdict needs | "Getting enough repos" (screener, extras file, `--fixed`, own targets) |
| undefined terms (Holm, tol, +G/+F, cvefix, volmatch, K-base) | glossary |
| the pre-registration template had no worked example | linked to `PREREG-alternatives.md` and `RESULTS-alternatives.md` |
| no cost or wall-time signal | `selftest` prints spend; the guide gives time expectations |

All were fixed and covered by tests (48 pass). This is one reader, not a user study: it shows the documentation gaps
a newcomer hits, not whether anyone outside will adopt the tool.

## 8. What it cost

$305.50 in all over 2,776 run records (list-price equivalent; Sonnet $192.72, Haiku $112.78): $124.49 for the
alternatives study and about $181 for the controls, the 34-repo extension and the patch-differential runs. The
placebo arm was the most expensive on Haiku ($0.24 per run on the CVE suite). Wall clock was dominated by Haiku on large repositories and by
sharing one machine across several run queues; Sonnet 51-repo arms ran at about one arm per hour.

## 9. Known limits of this battle test

- One task family (vulnerability finding), one model family for subject, verifier and the authors of the alternatives.
- The new repos are from one mechanical screener; several are clustered by project (fast-jwt, commonmark, ruby-sdk,
  coraza), which the repo-as-unit analysis does not fully account for.
- Handicap control harm is only visible on the high-baseline model; the truncation check covers the low-baseline one.
- No one outside the author has run the framework; a fresh-eyes subagent did (section 7) and its friction is fixed, and
  `ablate selftest` lets the first real outside user check the setup before relying on a verdict.
- Sonnet runs on the 34 new repos used 1 rep (Haiku 2); within-repo averaging is correspondingly thinner.
- Three defects flagged by automated review (Guardian Shadow) were fixed after the runs and covered by tests:
  the verify flag is now part of the run's config id (a `--no-verify` record can no longer satisfy a verified run;
  checked live), `--label` is refused for the baseline and the controls (A, O, H) and the record stores the real
  arm kind, and the notes wrapper is hashed with the notes. None affected the runs above, since each run directory
  used one setting. Records made before the fix carry the earlier config ids, so re-running into those directories
  stops with a "use a new run dir" error instead of reusing them; scoring and `verdict` do not check ids and read them as before.
