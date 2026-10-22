# Pre-registration: wide-class eval (written before any wide run)

Date: 2026-10-12. Suite `wide`: injection, authorization, business logic.

Comparison: B (current skills) vs B+gate. A (vanilla) is reported, not decisive.

Ship-as-default rule (same as the SSRF eval): pooled effective precision gain of at
least 15 points B to B+gate AND pooled recall loss under 10 points. Per-class numbers
are reported but do not decide. The SSRF result (+11.2) stays as is.

Also decisive, new: recall on the authorizer mix-up class (a bool-returning check
called where the throwing variant was meant, result ignored). If the gate loses more
than 1 of those true positives it is rejected regardless of precision.

Changes from the SSRF run: the generator prompt and verifier rubric are generalised
(`verifier-prompt-general.md`, fixed here, not tuned after seeing results); the run
cache is keyed by configuration; gold labels are checked for overlap. Gold lines
and decoys are authored before running and are not edited afterwards. If a label is
found wrong, it is reported as disputed, and results are shown both ways.

## Addendum (2026-10-12, written after the wide run, before the mixup run)

Wide run result (see RESULTS-wide.md): the authorizer mix-up class was at ceiling
(both arms found every seeded bug, no false positives on correct siblings), so it
could not discriminate. Suite `mixup` adds harder variants: missing `await` on an
async authorizer, an import alias that turns a bool check into a "require", an
ignored Go error return, a misleadingly named `requireRole` that returns a bool, a
near-identical decorator pair, and one clean repo. Each file wires its own routes
and identity so the verifier is not starved of context (the wide run lost true
positives as UNVERIFIABLE on single-file repos that never set `g.user`).
Exploratory: 3 reps per arm, same decision rule on recall (gate may lose at most 1
true positive pooled). It does not change the wide verdict.
