# Results: evidence-gated findings vs. current skills vs. vanilla

Date: 2026-10-11. Model: `sonnet` for generator and verifier. SSRF only.

## Verdict: REJECT as an always-on default; keep as an opt-in skill

Pre-registered rule (written before any run): ship if effective precision improves
by at least 15 points over the current harness with under 10 points of recall loss.
Measured B to B+gate: +11.2 points precision, 0 points recall loss. That misses the
bar. The direction is consistent, so the skill ships as opt-in for cases where false
positives are expensive, not as a default that adds ~50% cost per run.

Update 2026-10-12: a new overlap check in `score.py` found two label bugs in the SSRF
gold (a TP pattern that also matched an allowlisted call, and label windows that touched
adjacent decoys). Corrected and re-scored: numbers below are unchanged. Wider classes,
including authorizer mix-ups, are in `RESULTS-wide.md`; the verdict is unchanged.

## Setup

- 13 small synthetic repos (Python, Node, Go, PHP, Java, Ruby), each with 0-1 seeded
  true SSRF and 1-2 decoys (guarded path, admin-only route, constant URL, config
  value). 11 repos have a true bug; 2 are clean. `corpus/`, labels in `gold.json`.
  Gold lines resolve by regex in `score.py`, never from agent output.
- Arm A: vanilla (`--disable-slash-commands`, no project skills).
- Arm B: the `security-research` skill suite (see `../security-research`) available.
- Arm +gate: the same candidates as A/B, filtered by a fresh-context read-only
  verifier (`verifier-prompt.md`). The gate arms are not separate generations, so
  the only difference is the verifier.
- 3 runs per arm per repo, 78 generator runs, one verifier call per candidate.
- Corpus was widened after the first 8 repos hit a ceiling (A precision 0.91).
  That was a deliberate change after seeing data; all 13 repos are reported.

## Numbers (39 runs per arm)

| arm | TP | FP (decoy) | precision | recall | $/run |
|---|---|---|---|---|---|
| A vanilla | 33 | 10 | 0.77 | 1.00 | 0.039 |
| A + gate | 33 | 3 | 0.92 | 1.00 | 0.075 |
| B skills | 33 | 8 | 0.80 | 1.00 | 0.070 |
| B + gate | 33 | 3 | 0.92 | 1.00 | 0.105 |

- The verifier removed every admin-only decoy (h2, php-feed) and a substring decoy,
  and removed no true positive (33 of 33 retained).
- The skills alone moved precision by 3 points (0.77 to 0.80) at 1.8x cost. On this
  corpus the current skill stack is not clearly worth its tokens; the gate helped more.
- No false positive on either clean repo in any arm.

## A contestable label (does not change the verdict)

All 6 surviving false positives are one case, `h1-py-helper` `/fetch`: the code
resolves the host and rejects private IPs, then `requests.get` resolves it again.
Every verifier flagged that as a DNS-rebinding TOCTOU. I labelled it a decoy; that
label is arguably wrong, since resolve-then-fetch without pinning is a known bypass.
Treating it as a true positive lifts both sides (its findings are TPs in the
ungated arms too): B goes 0.80 to 0.88, B+gate to 1.00, a gain of +12 points; A to
A+gate goes 0.84 to 1.00, +16. So the relabel does not change the B-vs-gate verdict
(still under 15), and the verdict stands either way. I did not apply the relabel to the headline numbers, because
relabelling after seeing results favours the change under test. Decide the label
independently and re-score; the runs are in `runs/` (gitignored, regenerate with `run_eval.py`).

## Limits

- Synthetic apps, authored by the same person who wrote the verifier rubric. Real
  codebases are harder and the rubric's closing-guard rules match my labels.
- Verifier and generator are the same model family; a shared blind spot would not
  show up here.
- 3 repetitions per repo are correlated; the counts are small (10 and 8 decoy
  findings). No confidence intervals; do not read +11 vs +15 as a sharp boundary.
- One vulnerability class. Injection and authz are untested.

## Reproduce

    uv run python eval/run_eval.py --skills-dir <dir containing security-research/> --reps 3
    uv run python eval/score.py
