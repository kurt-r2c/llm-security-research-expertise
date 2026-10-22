---
name: evidence-gated-findings
description: Gate security findings behind an independent fresh-context verifier. Use when auditing code for vulnerabilities and you want only findings with a checked file:line trace, an attacker-controlled source and no closing guard to reach the report.
allowed-tools: Read, Grep, Glob
---

# Evidence-gated findings

An agent that finds a bug and then triages it grades its own work. This skill
splits the two: generation records each candidate with checkable evidence, and
a separate verifier with read-only tools tries to refute it. Only CONFIRMED
findings are reported.

## Protocol

1. Generate candidates. For each, write `findings/<id>.json` matching
   `schema/findings.schema.json`: claim, source, sink, a `trace` of
   `file:line` steps, and `guards_checked` (what validation sits on the path).
2. Verify each candidate in a fresh context (a subagent or `claude -p`) that
   has only Read/Grep/Glob, using `verifier-prompt.md`. The verifier receives
   the candidate JSON, not the generator's conversation. It returns a verdict
   per `schema/verdict.schema.json`. Write the verdict into the candidate file.
3. Report CONFIRMED findings. List REFUTED and UNVERIFIABLE separately with
   the verifier's reason, so a human can overrule it. A refutation is a
   claim, not a fact.
4. Optional: register `hooks/require-verdicts.sh` as a Stop hook so the final
   answer is blocked while any candidate has no verdict.

`harness.py` runs steps 1-2 headlessly through `claude -p`.

## Limits

- The verifier is the same model family as the generator and shares its blind
  spots. Treat it as a cheap second reader, not an oracle.
- The rubric in `verifier-prompt.md` is written for SSRF. Change the source
  and guard rules for other classes before reuse.
- Evidence is in `eval/RESULTS.md`; read the sample-size caveats there.
