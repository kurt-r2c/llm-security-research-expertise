# Settlement tests and pairwise comparison

Date: 2026-10-12. Criteria: `PREREG-settlement.md` (written after A/B/C CVE counts were seen, before arm D and
the final statistics). Models: sonnet and haiku. Arms: A vanilla; B skills listed; C vanilla plus `expertise/`
guides; D skills forced by instruction; +G verifier gate; +F gate with a maintainer facts note.

## Read this first

1. **Arm B never used the skills.** Tool traces: B skill-invoked in 0 of 156 runs. D (explicit
   instruction): 250 of 250. C read the guides in 198 of 250 runs (79 percent). Every earlier "skills vs
   vanilla" number in `RESULTS*.md` compared vanilla with vanilla plus a skill listing; the 30 to 80 percent
   cost gap was listing overhead. Only D tests the skills.
2. **Nothing is shown necessary.** Under the pre-registered rule no arm (skills, guides, forced skills)
   beats vanilla on recall for either model, on synthetic or post-cutoff-CVE bugs.
3. **One positive result:** a short maintainer facts note makes the gate strictly better (see test 4).
4. Statistics are by repo (reps of a repo are correlated), so n is 37 repos (synthetic) or 7 (CVE). Powerless
   for small effects; absence of a detected effect is not evidence of none.

## Results by settlement test

**Test 1, corpus (C vs A).** Synthetic: recall identical (ceiling), Sonnet and Haiku. Post-cutoff CVEs, Sonnet:
C found the fix site in 4 of 14 runs vs 3 of 14 for A (sign p=1.00). Haiku: C 4 of 14 vs A 8 of 14
(A minus C +0.286, p=0.38), so on the weaker model the guides did not help and may have hurt (findings per run
5.1 vs 6.6). Not shown necessary. Guide tree hash for all C runs: `bb6309d2d075`.

**Test 2, capability scaling.** No arm raised recall for Haiku either. On synthetic suites recall was
identical for A, B, C, D on both models. The hypothesis "skills/guides help weaker models more" is not
supported. What does scale with weaker models is the gate: Haiku pooled synthetic, gate cut false positives
by 0.36 to 0.60 per run (p about 0.00) at a recall cost of 11 to 14 points (p 0.01 to 0.03); Sonnet cut
0.06 to 0.12 per run at 0 to 4 points of recall.

**Test 3, invocation.** Traced: B 0 percent, D 100 percent. D vs A: Sonnet synthetic recall 0.000, FP +0.009
(ns); Sonnet CVE recall -0.071 (one run, p=1.00); Haiku CVE 0.000. Forced skills are not shown necessary
either.

**Test 4, facts note as stand-in for a context tool (Sonnet, wide+mixup, 63 seeded bugs per arm).**

| arm | raw found / FP | gate found / FP / unverifiable true bugs | gate+facts found / FP / unverifiable true bugs |
|---|---|---|---|
| A | 63 / 6 | 59 / 3 / 7 | 63 / 2 / 1 |
| B | 63 / 3 | 60 / 1 / 4 | 63 / 0 / 0 |
| C | 63 / 10 | 63 / 5 / 2 | 63 / 3 / 0 |
| D | 63 / 7 | 60 / 4 / 6 | not run |

With the note the gate loses no true positives and cuts false positives further than the plain gate. Pairwise
(by repo) the recall recovery is -0.048 to -0.063 with CIs touching 0, so by the pre-registered threshold it is
directional, not settled. Caveats: the note text was fixed before the re-verification but after I had seen the
gate's context-starvation failures, and it is tailored to these synthetic corpora ("identity is populated by
trusted middleware; callers exist"). It shows that supplying missing context fixes the failure; it does not show a
generic note would. A code-graph context tool and an executable-proof verifier were not built or tested.

**Test 5, corpus audit.** Done first. Adjudicated 15 clusters of non-gold findings blind to gate verdicts: 7 real
unintended bugs and 2 ambiguous became neutral, 6 stayed false positives. Strict scoring reproduces the original
numbers. Effect: vanilla and skills precision are near-perfect and the gate's precision edge shrinks (wide: 0).

## CVE suite detail (7 post-cutoff advisories from July to October 2026; fix hunks as gold)

Runs that landed on the fix hunk (A/B/C/D, 2 reps each): Sonnet fastjwt-unsigned 0/0/1/0; mariadb-nobs
1/2/1/2; mariadb-setkey 2/2/2/2; all others 0 for every arm, including the strawberry authorizer-awaitable
bug (0/0/0/0). Haiku finds more hits but emits about 6 findings per run against Sonnet's 1, so its higher raw
recall is partly volume. Precision is not measured here (other real bugs are unlabelled).

## Pairwise tables (X minus Y; positive FP = X has more false positives; CI by bootstrap over repos)

```
## Sonnet, synthetic (ssrf+wide+mixup pooled)  repos=37  runs/arm={'A': 111, 'A+G': 111, 'B': 111, 'B+G': 111, 'C': 111, 'C+G': 111, 'D': 111, 'D+G': 111, 'A+F': 72, 'C+F': 72, 'B+F': 72}
X vs Y       repos |    recall d(X-Y) [95% CI over repos]     p |                  FP d(X-Y)     p |  cost d
A vs B          37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.045 [+0.009,+0.090]  0.12 |  -0.019
A vs C          37 |               +0.000 [+0.000,+0.000]  1.00 |     -0.045 [-0.126,+0.027]  1.00 |  -0.066
A vs D          37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.009 [-0.054,+0.072]  1.00 |  -0.046
C vs D          37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.054 [-0.009,+0.117]  0.29 |  +0.020
A vs A+G        37 |               +0.042 [+0.000,+0.104]  0.50 |     +0.090 [+0.009,+0.189]  0.12 |  -0.043
B vs B+G        37 |               +0.031 [+0.000,+0.073]  0.25 |     +0.063 [+0.000,+0.144]  0.25 |  -0.041
C vs C+G        37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.117 [+0.036,+0.216]  0.03 |  -0.043
D vs D+G        37 |               +0.031 [+0.000,+0.083]  0.50 |     +0.063 [+0.009,+0.126]  0.12 |  -0.044

## Haiku, synthetic (pooled)  repos=37  runs/arm={'A': 111, 'A+G': 111, 'B': 111, 'B+G': 111, 'C': 111, 'C+G': 111, 'D': 111, 'D+G': 111}
X vs Y       repos |    recall d(X-Y) [95% CI over repos]     p |                  FP d(X-Y)     p |  cost d
A vs B          37 |               +0.000 [+0.000,+0.000]  1.00 |     -0.135 [-0.351,+0.045]  1.00 |  -0.002
A vs C          37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.171 [+0.018,+0.351]  0.29 |  -0.005
A vs D          37 |               +0.000 [+0.000,+0.000]  1.00 |     +0.153 [-0.018,+0.333]  0.29 |  -0.009
C vs D          37 |               +0.000 [+0.000,+0.000]  1.00 |     -0.018 [-0.198,+0.171]  1.00 |  -0.004
A vs A+G        37 |               +0.125 [+0.031,+0.229]  0.03 |     +0.477 [+0.306,+0.658]  0.00 |  -0.006
B vs B+G        37 |               +0.115 [+0.042,+0.198]  0.01 |     +0.595 [+0.378,+0.856]  0.00 |  -0.006
C vs C+G        37 |               +0.135 [+0.042,+0.250]  0.03 |     +0.387 [+0.234,+0.559]  0.00 |  -0.005
D vs D+G        37 |               +0.125 [+0.042,+0.229]  0.03 |     +0.360 [+0.198,+0.559]  0.00 |  -0.005

## Sonnet, post-cutoff CVEs  repos=7  runs/arm={'C': 14, 'C+G': 14, 'A': 14, 'A+G': 14, 'B': 14, 'B+G': 14, 'D': 14, 'D+G': 14}
X vs Y       repos |    recall d(X-Y) [95% CI over repos]     p |                  FP d(X-Y)     p |  cost d
A vs B           7 |               -0.071 [-0.214,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.000
A vs C           7 |               -0.071 [-0.214,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.077
A vs D           7 |               -0.071 [-0.214,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.026
C vs D           7 |               +0.000 [-0.214,+0.214]  1.00 |            n/a (unlabeled)   nan |  +0.051
A vs A+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.049
B vs B+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.058
C vs C+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.071
D vs D+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.073

## Haiku, post-cutoff CVEs  repos=7  runs/arm={'C': 14, 'C+G': 14, 'A': 14, 'A+G': 14, 'B': 14, 'B+G': 14, 'D': 14, 'D+G': 14}
X vs Y       repos |    recall d(X-Y) [95% CI over repos]     p |                  FP d(X-Y)     p |  cost d
A vs B           7 |               +0.000 [-0.286,+0.357]  1.00 |            n/a (unlabeled)   nan |  +0.024
A vs C           7 |               +0.286 [-0.071,+0.571]  0.38 |            n/a (unlabeled)   nan |  -0.004
A vs D           7 |               +0.000 [-0.286,+0.286]  1.00 |            n/a (unlabeled)   nan |  +0.038
C vs D           7 |               -0.286 [-0.429,-0.071]  0.12 |            n/a (unlabeled)   nan |  +0.041
A vs A+G         7 |               +0.071 [+0.000,+0.214]  1.00 |            n/a (unlabeled)   nan |  -0.030
B vs B+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.029
C vs C+G         7 |               +0.000 [+0.000,+0.000]  1.00 |            n/a (unlabeled)   nan |  -0.026
D vs D+G         7 |               +0.143 [+0.000,+0.286]  0.50 |            n/a (unlabeled)   nan |  -0.015

## Sonnet wide+mixup, facts note  repos=24  runs/arm={'D': 72, 'D+G': 72, 'A': 72, 'A+G': 72, 'A+F': 72, 'C': 72, 'C+G': 72, 'C+F': 72, 'B': 72, 'B+G': 72, 'B+F': 72}
X vs Y       repos |    recall d(X-Y) [95% CI over repos]     p |                  FP d(X-Y)     p |  cost d
A+G vs A+F      24 |               -0.063 [-0.159,+0.000]  0.50 |     +0.014 [+0.000,+0.042]  1.00 |  +0.001
B+G vs B+F      24 |               -0.048 [-0.111,+0.000]  0.25 |     +0.014 [+0.000,+0.042]  1.00 |  +0.001
C+G vs C+F      24 |               +0.000 [+0.000,+0.000]  1.00 |     +0.028 [+0.000,+0.083]  1.00 |  +0.001
A vs A+F        24 |               +0.000 [+0.000,+0.000]  1.00 |     +0.056 [+0.000,+0.153]  0.50 |  -0.045
```

## Limits

Small n (7 repos for CVE), one run configuration per cell, single-file synthetic repos, labels authored by me
with adjudication, same-family verifier, Haiku volume confound on CVE recall, cluster tests are coarse (sign p
with 7 repos cannot go below 0.016). Run records before 2026-10-12 lack a config id (legacy); C was added to
existing run directories under the same settings except the guide-hash key added afterwards.
Arm D and every arm now deny the Bash tool (the skill's `allowed-tools: Bash(*)` otherwise grants it).
