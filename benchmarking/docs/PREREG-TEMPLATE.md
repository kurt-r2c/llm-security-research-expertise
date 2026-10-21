# Pre-registration: <harness name> versus the raw model

A filled-in example is `docs/PREREG-alternatives.md` (with its dated addendum), judged by `docs/RESULTS-alternatives.md`.
Copy this file to `docs/PREREG-<name>.md`, fill it in, commit it, and only then start the runs.
A rule written after the data is a description, not a test. Later additions go in a dated addendum.

## What is being tested

- Harness under test: <what it adds to the raw model: prompts, skills, guides, tools, pipeline stages, a verifier>
- Raw baseline: arm A, the same model through `claude -p` with the same tools and no additions
- Models: <aliases, and the date they were resolved>
- Why you expect it to help, in one sentence, and what you expect NOT to change

## Disclosure

- What you had already seen (earlier runs, a failing case you wrote the harness to fix)
- Who wrote the harness text and whether they saw the benchmark data

## Design

- Suites: <ssrf / wide / mixup / cve / cvefix / your own>, repos per suite, reps
- Arms: A (baseline), your harness (as `--arm-cmd` or a built-in arm), P (placebo of the same length and
  delivery, content-free), O (oracle, positive control), H (handicap, negative control)
- Power: output of `ablate power` on a pilot, and the smallest recall gain you can detect at 80%
- Calibration: output of `ablate calibrate` (false-pass rate of the rule on your data)

## Decision rule

Commit `rule.json` (see `rule.example.json`) next to this file. State in words:

- Primary test: one per candidate and model; pooled recall difference, repo as the unit
- Multiple comparisons: Holm over all (candidate, model) tests
- Harm floor and precision floor
- Delivery check (was the added material actually read or invoked?)
- How truncated or failed runs count
- What DISCARD means (not shown at this power, not "useless")

## Controls that must behave before the verdict is believed

- O must show a significant gain; H must show harm; the raw-model adapter must tie with A
- If a control fails, the result is "framework not sensitive here", not KEEP or DISCARD

## Not tested (state it)
