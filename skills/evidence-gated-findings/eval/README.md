# eval

`corpus/`, `corpus-wide/` and `corpus-mixup/` are deliberately vulnerable synthetic code.
Do not deploy it. Security scanners will flag it; that is expected, and the labels in
`gold*.json` say which sites are the seeded bugs and which are decoys.

Suites (`suites.py`): `ssrf`, `wide`, `mixup`. Runs are stored under
`runs/<suite>-<config hash>/` (gitignored); the hash covers the model, prompts, schemas,
corpus and skills, so a changed setting never reuses old runs.
Scoring: `score.py` resolves gold sink lines by regex and refuses to run if a true
positive and a decoy label are close enough to be confused.

Results: `RESULTS.md` (ssrf), `RESULTS-wide.md` (wide and mixup). Pre-registration:
`PREREG-wide.md`.
