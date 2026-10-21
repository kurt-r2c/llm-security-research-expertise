# Auditing a harness against the raw model

Question this answers: **does the thing you built around a frontier model find more real bugs than the
model alone, by more than noise, at a cost you accept?** Harnesses carry labour and maintenance; the
raw model gets better every release. Run this audit at each model release and delete what does not
pay for itself.

The framework is `ablate` in this repository. It is model-API-agnostic at the edge (your harness is a
shell command) and uses `claude -p` for the raw baseline and for the independent verifier.

## The audit in eight steps

Before step 1, run `ablate selftest` once on your machine, model and suite (a few dollars on Haiku). It checks that the
oracle shows a gain, an adapter ties the baseline, the handicap shows harm and A/A splits do not pass; a FAIL means the
suite is too small or the setup is off, and no verdict from it can be trusted yet.

1. **Write down what you expect.** Copy `docs/PREREG-TEMPLATE.md`. One sentence on why the harness should
   help and what it should not change. Commit before running anything.
2. **Wrap your harness as an adapter** (below). Wrap the raw model too with the same tools
   (`examples/adapters/raw_claude.sh` is the template); it must tie with built-in arm A.
3. **Pick suites.** Synthetic suites (`wide`, `mixup`, `ssrf`) have complete gold and measure precision
   but saturate on strong models. The real-CVE suite (`cve`, post-cutoff advisories) measures recall on
   bugs the model has not memorised. `cvefix` runs the same projects at the fix commit and gives the
   CVE suite a precision proxy (see Metrics). Bring your own suite by adding a corpus directory and a gold file.
4. **Check you have the power.** `ablate power` simulates the decision rule from a pilot of the raw
   model. If the minimum detectable gain is bigger than any gain you would believe, add repos, not reps.
5. **Run the controls.** The O (oracle) arm must show a clear gain, the raw-model adapter must tie with A,
   and `ablate calibrate` must show a false-pass rate near or below alpha. Only then does a null mean something.
6. **Run the arms** with at least a placebo (P: same length and delivery as your harness text, no
   content) next to your harness, on every model you care about.
7. **Apply the pre-written rule**: `ablate verdict --rule rule.json --in MODEL:SUITE:RUNDIR ...`.
8. **Report**: copy the layout of `docs/RESULTS-alternatives.md` (a filled-in example; `docs/PREREG-alternatives.md` is the matching filled-in pre-registration): verdict table, per-suite numbers,
   volume and cost, limits. A DISCARD means "not shown at this power".

## Minimal first audit (about an hour, a few dollars on Haiku)

Your harness is `my_harness.sh` (see the adapter contract below). Single quotes keep your shell from expanding
`$HARNESS_LAUNCH_DIR`. Both commands must write to the SAME run directory, because `verdict` reads one directory per
`--in`; run them from the repository root so the script path resolves.

```
uv run ablate selftest --model haiku                               # once: do the controls behave here?
R=runs/first/cve-haiku
uv run ablate run --suite cve --reps 2 --model haiku --arms A --run-dir $R
uv run ablate run --suite cve --reps 2 --model haiku --arm-cmd 'mine=bash $HARNESS_LAUNCH_DIR/my_harness.sh' --run-dir $R
echo '{"baseline":"A","placebo":null,"candidates":["mine"]}' > rule.json    # commit this BEFORE the runs
uv run ablate verdict --rule rule.json --in haiku:cve:$R
```

Expect it to be slow and quiet: each record is written when its run ends, the CVE suite takes tens of minutes per arm
on Haiku and an hour or more on Sonnet, and `selftest` prints the spend at the end. With fewer than about 50 repos the
verdict will almost always be DISCARD for lack of power; that is the tool being honest, not your harness failing.

## Getting enough repos

`ablate build-cve` stages the 17 original post-cutoff advisories (needs an authenticated `gh`). To widen the suite:

```
uv run python -m harness_ablation.screen --since 2026-07-01 --want 36 --per-bucket 5 --out cands.json
# review cands.json, then save the entries you want as data/cve-specs-extra.json (id, repo, sha, ghsa, sub, files)
uv run ablate build-cve            # pre-fix trees and gold from the fix diff
uv run ablate build-cve --fixed    # fix-commit trees, for the patch-differential precision proxy (cvefix suite)
```

The screener picks by mechanical rules and never looks at model results. Check each gold hunk against its advisory
before relying on it. To use your own targets instead, add a corpus directory and a gold file in the shape of
`data/gold-cve.json` (`{repo: {"cls": "cve", "advisory": id, "tp": [{"file", "from", "to"}]}}`, line ranges of the
buggy code) and a `SUITES` entry in `suites.py`.

## Rule file reference (`rule.json`)

| key | meaning |
|---|---|
| `baseline` | arm name of the raw model (A) |
| `candidates` | arms being judged (a label you gave an arm, or the label of an `--arm-cmd`) |
| `placebo` | arm of a same-length, no-content control, or `null` to run without one. When set, a candidate must also beat it |
| `mode` | `""` judges raw findings; `"G"` judges only findings the independent verifier (gate) confirmed |
| `alpha` | significance level before the Holm adjustment (default 0.05) |
| `harm_floor` | pooled recall difference (a fraction of seeded bugs, so -0.05 is five points) below which a candidate is discarded |
| `precision_floor` | same, for precision on the synthetic suites; skipped if you run only CVE suites |
| `delivery` | per candidate, `{"min_read_fraction": 0.5, "read_marker": "/expertise/"}`: the candidate is judged only if its added material was opened in that share of runs. Omit it for a harness with no read-on-demand material |
| `truncation_flag` | discard if the candidate's share of unfinished runs exceeds the baseline's by more than this |

Keys beginning with `_` are ignored, so you can annotate the file. Output columns: `K-base` is candidate minus baseline
pooled recall with a bootstrap 95% CI over repos; `p` the exact sign test over repos that differ; `holm` the p after
Holm's step-down correction over all (candidate, model) tests; `K-placebo` candidate minus placebo.

## Glossary

- **Arm**: one configuration run on the same targets (A baseline, O oracle, H handicap, P placebo, or yours).
- **Recall**: share of seeded or fixed bugs a run found, a finding within `tol` lines (2 synthetic, 5 CVE) of the bug.
- **+G**: findings kept by the fresh-context verifier ("gate"); **+F**: the same verifier given a facts note.
- **Holm**: a correction for running several tests at once; a gain must survive it to count.
- **Placebo**: text of equal length and delivery with no domain content, to separate content from prompt length.
- **cvefix**: the same projects at the fix commit; a finding at the fixed site is a false alarm (`ablate fixcheck`).
- **volmatch**: recall compared with the baseline downsampled to the candidate's findings volume.

## Adapter contract

```
ablate run --suite cve --reps 2 --model sonnet \
  --arm-cmd 'mine=bash $HARNESS_LAUNCH_DIR/my_harness.sh' --run-dir runs/cve-sonnet-mine
```

Your command runs through `bash -c` inside a scratch copy of the target repo (so runs cannot see each
other or the gold file) with these environment variables: `HARNESS_MODEL`, `HARNESS_SUITE`,
`HARNESS_PROMPT` (the audit instruction), `HARNESS_SCHEMA_FILE` (the findings JSON schema) and
`HARNESS_LAUNCH_DIR` (where `ablate` was started). It prints one JSON object on stdout:

```
{"findings": [{"file": "src/a.py", "line": 12, "trace": [{"file": "src/a.py", "line": 12, "note": "..."}], ...}],
 "cost_usd": 0.31}
```

Only `file` and `line` are required per finding (missing fields are filled in); put the sink line in
`trace` last if the reported line is the source. A non-zero exit keeps the findings and records the
status (`exit_N`); a timeout or unparsable output records `timeout` or `bad_output` with no findings, and
the verdict reports the truncation rate. Non-LLM tools work too: `examples/adapters/semgrep_oss.py`
runs Semgrep rules as a harness (use `--no-verify` to skip the LLM verifier gate).

Same-model fairness: give the raw arm and your harness the same model alias, the same read-only
tools and the same per-run budget. Do not let the harness see the gold file (staging guarantees it
cannot), and do not tune it on the audit repos.

## Controls: why they are in the framework

| Control | Arm | Expected | If it fails |
|---|---|---|---|
| Positive | `O` names the file that holds each seeded bug | clear recall gain | the suite or rule cannot see gains; add repos |
| Negative | `H` gives the run a near-zero budget | recall drop, truncation flagged | the rule cannot see harm; check headroom |
| Adapter | raw model through `--arm-cmd` | ties with A | your adapter changes the model's behaviour |
| Placebo | `P` content-free text of equal length | ties with A | length alone moves results; subtract it |
| A/A | `ablate calibrate` | false-pass rate at or below alpha | the rule is too liberal for this data |
| Drift | old run of arm A vs new (`--other`) | difference near zero | session-to-session noise sets your floor |

## Metrics

- **Recall** per run: seeded or fixed bugs found, within `tol` lines (2 synthetic, 5 CVE). The unit of
  analysis is the repo, since reps of one repo are correlated.
- **Precision** (synthetic suites): false positives per run and TP/(TP+FP), with decoys labelled.
- **Gate (+G)**: a fresh-context read-only verifier filters candidates; the same verifier is applied to
  every arm so only the generator differs.
- **Patch-differential precision proxy** (`ablate fixcheck`): hit rate on the pre-fix tree minus alarm
  rate on the fix tree. A harness that cannot tell fixed from vulnerable code scores 0.
- **Volume**: findings per run, and `ablate volmatch`: the candidate's recall against the baseline downsampled to
  the candidate's volume. A recall loss or gain that is only volume is not a judgement effect.
- **Cost**: list-price cost per run, reported, not decisive.

## Decision rule (what `ablate verdict` implements)

For each candidate and model: pooled recall difference over all suites, bootstrap 95% CI over repos
and an exact sign test; Holm adjustment over all (candidate, model) tests. KEEP needs CI above 0 and
Holm p below alpha on at least one model; no model below the harm floor; precision not below its floor
on the synthetic suites; the candidate above the placebo where it passes; the delivery check satisfied
(was the added material actually read or invoked?); truncation within bounds. Everything else is DISCARD.

## Pitfalls found while building this

- A skill that is only listed is not used (0 of 156 runs invoked it). Measure invocation, or force it.
- A longer prompt is not a better prompt: use the placebo arm before crediting content.
- Strong models saturate synthetic suites; the CVE suite is the only place recall can move.
- Most real bugs are missed by every arm (43 of 51 CVE repos on Sonnet), so few repos carry any
  signal. Power comes from more repos, not more reps: 17 repos could only see gains above 0.20, 51 reach about 0.10 on
  Sonnet. Run `ablate power` before spending on arms.
- A "content-free" placebo that tells the model to be systematic is an effort prompt: it lifted Sonnet by +0.10.
  Make the placebo carry no instructions, and treat "be thorough" as a baseline your harness must beat.
- Harm is invisible when the baseline is near zero; keep the truncation check next to the harm floor.
- Findings volume confounds recall on weaker models. Report findings per run.
- Do not hash only the prompt: the config id covers model, prompts, schemas, corpus, guides, notes
  and arm settings so a changed setting never silently reuses old runs.
- The gate can cost recall; test it as its own arm (+G) rather than assuming it is free.
- Each run stages a scratch copy of the target; the harness deletes it when the run ends (an earlier version
  left them behind and filled 8 GB of disk during the study). Check free disk before large queues.
- Truncated runs (budget exhausted) must count against the arm; never drop them.
- The raw baseline drifts between sessions by a few points; always run a concurrent A.
