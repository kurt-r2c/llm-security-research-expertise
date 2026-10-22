# harness-ablation

An ablation harness for LLM security-research scaffolding. It answers one question per model
release: does the thing I added to the prompt or the pipeline (skills, reference guides, a
maintainer facts note, an independent verifier) find more real bugs than vanilla, by more than noise?

It was built for the talk "So Long And Thanks For All The Compute". The tests in `docs/` retired
most of the scaffolding the talk started with, and the method is the part meant to be reused:
pre-register a decision rule, run vanilla against each addition on the same targets, score against
gold the agent never sees, and delete what does not beat noise.

## What it does

- Runs `claude -p` (Claude Code, headless, read-only tools, Bash denied) over a suite of repos.
- Arms: **A** vanilla, **B** skills available, **C** reference guides available, **D** skills forced,
  **E** facts note prepended. Gates: **+G** a fresh-context verifier filters the candidates,
  **+F** the verifier is given the facts note. Gate arms re-use the generator's candidates, so the
  only difference is the verifier.
- Scores findings against gold resolved by regex (synthetic suites) or by fix-hunk line ranges
  (real CVEs). Gold lines are never taken from agent output, and the staged copy of a repo never
  contains the gold file.
- Compares arms pairwise with the repo as the unit: bootstrap 95% CI over repos plus an exact sign
  test on the non-tied repos.
- Keys every run record by a hash of the model, prompts, schemas, corpus, skills, guides and facts
  note, and refuses to reuse a record made under a different configuration.

## Suites

| Suite | Targets | Gold |
|---|---|---|
| `ssrf` | 13 synthetic repos (seeded SSRF, decoys, clean repos) | regex-resolved sink lines |
| `wide` | 17 synthetic repos (injection, authorization, logic) | regex-resolved sink lines |
| `mixup` | 7 synthetic repos (closely named authorizer mix-ups) | regex-resolved sink lines |
| `cve` | 17 real advisories with fix commits on or after 2026-07-01 | fix-hunk ranges, 5-line window |

The synthetic repos in `data/corpus-*` are deliberately vulnerable. Do not deploy them. Security
scanners will flag them; the labels in `data/gold-*.json` say which sites are seeded bugs and which
are decoys. The CVE suite is not shipped: `ablate build-cve` downloads the pre-fix source of each
public advisory with an authenticated `gh` into `data/corpus-cve/` (gitignored third-party code).

## Use

```
uv sync
uv run pytest                                    # offline: gold integrity, scoring, statistics, config hash
uv run ablate build-cve                          # once, for the cve suite
uv run ablate run --suite wide --arms A --reps 3 --model sonnet
uv run ablate run --suite wide --arms C --guides-dir PATH_TO_GUIDES_WITH_INDEX_MD
uv run ablate run --suite wide --arms BD --skills-dir PATH_TO_SKILLS   # needs a security-research/ skill
uv run ablate reverify --suite wide --run-dir runs/wide-sonnet-<id>      # adds +F verdicts
uv run ablate score --suite wide --run-dir runs/wide-sonnet-<id> --by-class
uv run ablate pairwise --in wide:runs/wide-sonnet-<id> --pairs A:C,A:A+G,A+G:A+F
```

Skills and guides are not shipped; bring your own. Needs the `claude` CLI, authenticated, and `gh`
for the CVE suite. Models are passed as aliases (`sonnet`, `haiku`); run records store the alias,
so note which model ID it resolved to on the day you ran.

## Data handling

Every run sends the target code to the model provider. The shipped corpora are synthetic or public.
Do not point this at code you are not allowed to send to a third party. Run records contain model
output about the target and are gitignored (`runs/`).

## Results in one paragraph

On Sonnet 5.5 and Haiku 5.5, no arm beat vanilla on recall under the pre-registered rule, on
synthetic bugs or on 17 post-cutoff CVEs. A skill suite that was merely listed was never invoked
(0 of 156 runs). A verifier gate raised precision, a lot for Haiku and little for Sonnet, at a recall
cost and 50 to 100% more cost per run. A facts note helped a verifier on synthetic suites and did
not transfer to real CVEs. "Not shown necessary" is not "shown useless": 17 repos and 2 reps is
little power, CVE recall is confounded by findings volume, and the CVE suite has no precision
measure. Details and the limits are in `docs/`. A code-graph context tool and an executable-proof
verifier were not tested.

## Layout

```
src/harness_ablation/   harness (claude -p wrapper), suites, run, score, pairwise, reverify, build-cve
src/harness_ablation/data/   output schemas and verifier prompts
data/                   synthetic corpora and gold labels; corpus-cve/ is built locally
docs/                   METHOD, pre-registrations, results
tests/                  offline tests
```

## License

MIT. See `LICENSE`.
