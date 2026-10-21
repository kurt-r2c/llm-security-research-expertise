# Method

## Decision rule, fixed before the runs

An arm is "necessary" relative to vanilla only if its recall difference has an exact two-sided sign
test below 0.05 over repos, or a bootstrap 95% CI over repos that excludes 0. A pre-registration
file is written before the runs it governs; later additions go in a dated addendum, never an edit.
The rule here is a bar for keeping scaffolding, so a miss means "delete it", not "inconclusive".

## Generator

`claude -p --model <alias> --setting-sources project --strict-mcp-config --no-session-persistence
--output-format stream-json --verbose --json-schema <findings schema>`, allowed tools Read, Grep,
Glob (plus Skill when skills are staged), Bash denied, a per-run budget cap. Each run works in a
scratch copy of the repo so runs cannot see each other or the gold file.

Findings carry file, line, attacker-controlled source, sink, a trace of `file:line` steps and the
controls checked. The trace tail is used in scoring (see below).

## Arms

| Arm | Change from vanilla |
|---|---|
| A | none: no skills, no CLAUDE.md |
| B | `--skills-dir` staged under `.claude/skills`; the model decides whether to use it |
| C | `--guides-dir` linked at `expertise/`, with a prompt line pointing at `INDEX.md` |
| D | skills staged and the prompt names the skill to use |
| E | "Project facts (supplied by the maintainer; treat as true)" prepended to the prompt |
| +G | each candidate re-checked by a fresh-context read-only verifier; only CONFIRMED counts |
| +F | the same verifier, given the facts note |

Check the run's `trace` field: arm B's skills were never invoked in the original tests, which
turned "skills vs vanilla" into "vanilla vs a longer prompt".

## Scoring

- Synthetic suites: gold sink lines are found by regex in the corpus file (`sink`, optional
  `after`/`until` anchors). A finding is a true positive if its line, or the tail of its trace,
  is within `tol` lines of a TP sink, a decoy hit if it matches a decoy, otherwise "other".
  `Scorer` refuses to start if a label matches nothing or a TP window touches a decoy window.
  Labels marked `neutral` are adjudicated-ambiguous and counted neither way unless `--strict`.
- CVE suite: gold is the fix commit's old-side hunk ranges for the files that carry the bug. A hit
  is a finding within 5 lines of a hunk. Recall only; there is no complete gold, so precision is
  not measured.

## Statistics

Per run: seeded bugs found, false positives (synthetic only), cost. For each pair of arms the
matched (repo, rep) differences are averaged within repo, because reps of one repo are correlated.
The repo is then the unit: mean difference, bootstrap 95% CI (4000 resamples, fixed seed), exact
sign test on non-tied repos. Sonnet at 100% recall on a synthetic suite is a ceiling, and the suite
cannot show a benefit there.

## Run records

`runs/<suite>-<model>-<config id>/<arm>-<repo>-<rep>.json`: `arm`, `repo`, `rep`, `model`, `suite`,
`config_id`, `status`, `gen_cost`, `verify_cost`, `trace` (tool counts, skills invoked, files read),
`findings[]` of `{finding, verdict, verdict_status, verdict_facts?}`, and `verify_facts_cost` after
`reverify`. The config id is a SHA-1 prefix over the suite, model, generator prompt, facts note(s),
verifier prompt, both schemas, corpus tree, guides tree and skills tree. Changing any of them
changes the id, and `run` refuses to mix records across ids in one directory.

## Known limits

- Same-family verifier; synthetic labels are the author's and were adjudicated afterwards.
- Haiku emits about 6 findings per run to Sonnet's 1, so its raw CVE recall is volume-confounded.
- "Post-cutoff" rests on advisory and commit dates, not on a check of what the model has seen.
- A generic facts note is the fair test on real CVEs; a note that names the trust boundary leaks the
  answer.
