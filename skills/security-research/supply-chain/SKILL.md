# Supply Chain Security Audit

Audit the codebase for 3 supply chain vulnerability classes: dependency integrity
gaps, build pipeline injection points, and missing third-party code review gates.

---

## Quick Scope

Locate and examine the following before beginning checks:

- Package manifests: `package.json`, `requirements.txt`, `Gemfile`, `go.mod`,
  `pom.xml`, `build.gradle`, `Cargo.toml`, `pyproject.toml`, `*.csproj`
- Lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`,
  `go.sum`, `poetry.lock`, `uv.lock`, `Cargo.lock`, `*.resolved`
- CI/CD configs: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`,
  `Dockerfile`, `.circleci/config.yml`, `azure-pipelines.yml`
- Dependency update configs: `.github/dependabot.yml`, `renovate.json`,
  `.renovaterc`, `.renovaterc.json`
- Branch protection settings (if accessible via API or config-as-code)

---

## Check 1: Dependency Pinning — Unpinned version ranges in production manifests

**Find:** Version specifiers that allow the package manager to select any
future version at install time. Flag any of the following in production
manifests (not dev/test-only):

- npm/yarn: `^`, `~`, `>=`, `*`, `x` wildcards in `package.json` `dependencies`
- pip: `>=`, `~=`, `!=` without an upper bound; no version constraint at all
- Ruby: `~>` with only a major component; `>=` without upper bound in `Gemfile`
- Maven/Gradle: `RELEASE`, `LATEST`, `+` suffix, open `[1.0,)` ranges
- Cargo: `*` wildcard; ranges without an upper bound where a lockfile is absent

**Evaluate:** Check whether a lockfile exists and is committed. If a committed
lockfile pins all transitive dependencies to exact versions, an unpinned range
in the manifest is a lower-severity policy concern rather than an immediate
injection risk. If no lockfile is present, unpinned ranges in the manifest are
the sole version control mechanism and the risk is immediate.

Run `semgrep --config rules/supply_dependencies .` and reconcile tool findings
with the manifest enumeration above.

**Severity:** HIGH if an unpinned range exists in a production manifest AND no
lockfile is committed; MEDIUM if a lockfile is committed but the manifest still
allows silent drift on lockfile regeneration; LOW if only dev/test dependencies
are unpinned.

**Common false positives:** Internal monorepo cross-references using `*` or
`workspace:*` syntax — these resolve only to local packages and carry no
external supply chain risk.

---

## Check 2: Dependency Integrity — Missing cryptographic hashes in lockfiles

**Find:** Lockfile entries that do not include a cryptographic hash (SHA-256 or
equivalent) for each resolved artifact. Also flag:

- Direct git source references to branch names (e.g. `git+https://...#main`) or
  mutable tags (e.g. `#v1`) rather than a full commit SHA
- Dependencies declared without any lockfile equivalent (package manager in use
  but lockfile absent from the repository)

**Evaluate:** Confirm that the lockfile format for the package manager in use
supports per-package hashes. Some lockfile formats (e.g. `go.sum`) include
hashes natively; flag only when the hash field is absent or empty. For git
source references, a full 40-character commit SHA is the only acceptable pin.

Run `semgrep --config rules/supply_dependencies .` and reconcile tool findings.

**Severity:** HIGH if a dependency has no hash and no committed lockfile
provides integrity assurance; HIGH if a git source uses a branch name or
mutable tag; MEDIUM if hashes are present but the lockfile itself is not
committed (hash verification occurs only in CI, not on developer machines).

**Common false positives:** Lock entries for optional or peer dependencies that
the package manager does not hash by design (e.g. npm optional dependencies
in some older lockfile versions) — research the specific package manager
behaviour before flagging.

---

## Check 3: Build Pipeline — Mutable action and image references

**Find:** In CI/CD pipeline definitions, locate:

- GitHub Actions `uses:` references that specify `@main`, `@master`,
  `@latest`, or any branch name rather than a full commit SHA
- Docker image references using `:latest` or a mutable tag without an image
  digest (`@sha256:...`)
- Pipeline steps that fetch and execute a script from an external URL at
  runtime without integrity verification (e.g. `curl ... | bash`,
  `wget -O- ... | sh`, `Invoke-Expression (Invoke-WebRequest ...)`)

**Evaluate:** A mutable ref means a compromised upstream repository can inject
arbitrary code into the pipeline on the next run. Confirm the reference is
actually consumed in a pipeline step (not merely commented out or in a
template that is never instantiated). For runtime script fetches, check
whether a `--checksum` flag, `sha256sum` verification step, or equivalent
integrity gate follows the download before execution.

Run `semgrep --config rules/supply_pipeline .` and reconcile tool findings.

**Severity:** HIGH if a mutable action ref or `:latest` image is used in a
step that has access to secrets or writes to a production environment; HIGH if
a runtime-fetched script is executed without integrity verification; MEDIUM if
mutable refs exist only in steps with no secret access and no production write
path; LOW if the mutable ref is in a non-production or manual-only workflow.

**Common false positives:** Internal action references within the same
organisation's repositories where the org controls the ref target — still flag
but note the reduced blast radius. `@v1` style version tags that resolve to a
pinned SHA via GitHub's tag-locking mechanism are acceptable only if the
action author explicitly documents this; treat ambiguous cases as MEDIUM.

---

## Check 4: Build Pipeline — Overly broad secret scoping

**Find:** Secrets or credential environment variables declared at the top-level
`env:` block of a workflow file (making them available to all steps) rather
than scoped to only the specific job or step that requires them. Also flag:

- Secrets passed as environment variables to steps that perform untrusted code
  execution (e.g. steps running PR-contributed code, third-party actions with
  mutable refs)
- `pull_request_target` workflows that check out PR code and then access secrets

**Evaluate:** Determine which steps actually consume the secret. If the secret
is declared globally but only one step uses it, the scope is broader than
necessary. For `pull_request_target`, check whether the workflow checks out the
PR branch (`ref: ${{ github.event.pull_request.head.sha }}`) and subsequently
runs code from that branch with access to secrets — this is a confirmed
exfiltration path.

Run `semgrep --config rules/supply_pipeline .` and reconcile tool findings.

**Severity:** HIGH if a secret is accessible to a step executing untrusted
PR-contributed code or a mutable third-party action; HIGH for
`pull_request_target` + PR checkout + secret access combination; MEDIUM if a
secret is globally scoped but no step executes untrusted code; LOW if the
secret is scoped to a single job but could be further narrowed to a single step.

**Common false positives:** Secrets used in matrix jobs where every cell
legitimately needs the credential.

---

## Check 5: Third-Party Code Review — Automated updates merging without a review gate

**Find:** Dependency update configurations (Dependabot, Renovate) that are
configured to auto-merge pull requests to the default branch without requiring
human review. Look for:

- Dependabot: a companion GitHub Actions workflow that calls the GitHub
  auto-merge API on Dependabot PRs
- Renovate: `"automerge": true` at the global or per-package level
- Branch protection rules that have zero required reviewers on the default
  branch (making any PR mergeable without review)
- The complete absence of any dependency update configuration combined with no
  documented manual update policy

**Evaluate:** Distinguish between auto-merge gated on CI passing (acceptable
risk reduction but not zero-risk) and unconditional auto-merge. Confirm that
branch protection actually enforces required reviews by checking whether
`required_pull_request_reviews` is configured with at least one required
approver, or by inspecting the repository settings if accessible.

Run `semgrep --config rules/supply_review .` and reconcile tool findings.

**Severity:** HIGH if auto-merge is enabled with no required human review and
no branch protection enforcing approval; HIGH if an LLM agent or automation
installs dependencies in response to a prompt without human confirmation (gate
bypassed entirely — see agent runtime triage below); MEDIUM if auto-merge is
enabled but gated on CI passing with at least one status check; LOW if no
auto-merge is configured but branch protection requires zero reviewers.

**Common false positives:** Auto-merge limited to patch-level updates from
verified bot accounts where the organisation has an explicit documented policy
accepting this risk.

**Agent runtime note:** For applications that support user-installed plugins or
skills, apply the triage rules for agent runtimes before scoring:
install-time gate failures (non-blocking scanner, missing hash verification,
scan result not shown before confirm) → HIGH; runtime isolation gaps → LOW or
design observation; autonomous LLM-driven install without human confirmation
→ HIGH regardless of other controls.

---

## Check 6: AI-Agent Workflow Injection

**Find:** In CI/CD pipelines that invoke AI coding agents (Claude Code Action,
Gemini CLI Action, OpenAI Codex Action, GitHub AI Inference), identify injection
vectors where untrusted event data reaches the AI agent's prompt.

Examine five vectors:

- **Vector A — Environment variable intermediaries:** Event data flows through
  an `env:` block (e.g. `PR_TITLE: ${{ github.event.pull_request.title }}`) and
  is then consumed by the agent as a prompt argument. The `${{ }}` expression is
  absent from the agent invocation step itself, making this the most commonly
  missed vector. Flag any `env:` key populated from `github.event.*` that flows
  to an AI agent prompt.
- **Vector B — Direct expression injection:** A `${{ github.event.* }}` expression
  is placed directly in a field consumed as the AI agent's prompt or instruction
  (e.g. `prompt: "Review PR: ${{ github.event.pull_request.title }}"`). Any
  attacker-controlled PR title, body, comment, or branch name can inject
  instructions into the agent.
- **Vector D — `pull_request_target` + PR checkout + AI agent with secret
  access:** A `pull_request_target` trigger checks out the PR head SHA
  (`ref: ${{ github.event.pull_request.head.sha }}`) and runs an AI agent step
  that has access to repository secrets. The agent runs attacker-controlled code
  with access to production secrets — confirmed exfiltration path.
- **Vector F — Subshell expansion in restricted tool lists:** An AI agent's
  allowed-tool list contains a shell invocation with an expandable expression
  (e.g. `Bash(echo $SECRET)` or `Bash(cat /proc/self/environ)`). Shell expansion
  at execution time bypasses the intended restriction, leaking secrets or enabling
  command injection despite the apparent allowlist.
- **Vector H — Dangerous sandbox settings:** The agent workflow sets
  `sandbox: danger-full-access` (Codex), uses `Bash(*)` as an allowed tool (which
  disables all command guards), or runs with `--dangerously-skip-permissions`.
  These settings remove all safety controls and must be flagged regardless of
  other mitigations.

**Evaluate:** For each vector, confirm the event-data field is attacker-controlled
(PR title/body, issue comment, commit message, branch name, label name are all
attacker-controlled on public repositories). Confirm the agent has access to
at least one secret or can write to a persistent store. Check whether any
`if:` condition on the step restricts execution to trusted authors — note that
author checks based on `github.actor` are bypassable via fork PRs.

**Severity:** CRITICAL for Vector D (confirmed secret exfiltration path with
`pull_request_target` + PR checkout + secret access); HIGH for Vectors A, B, F,
and H when the agent has secret access or write capability; MEDIUM if the agent
has no secret access and write capability is limited to PR comments only.

**AI-Workflow Rationalizations to Reject:**

- **"Only maintainers can trigger this workflow"** is disproven by
  `pull_request_target` combined with an external PR that checks out
  attacker-controlled code — the trigger fires for any PR contributor.
- **"The action is pinned to a SHA"** mitigates Vector A/B only if the
  prompt-construction code in the action does not embed event data — verify the
  action's own source at the pinned SHA.
- **"The `if:` condition filters untrusted actors"** must use
  `github.event.pull_request.head.repo.fork == false` or equivalent — checks
  based on `github.actor` membership are bypassable.
- **"The tool list is restricted"** does not address subshell expansion (Vector F)
  or `Bash(*)` wildcards (Vector H) — review the exact strings in the allowlist.
- **"The agent is sandboxed"** does not protect against prompt injection that
  causes the agent to exfiltrate data through a permitted outbound channel or
  embed secrets in a PR comment.

---

## Rationalizations to Reject

Do not accept these justifications for skipping or downgrading a supply-chain
finding without completing the full evidence chain:

- **"Only maintainers can trigger this workflow"** is disproven by
  `pull_request_target` combined with an external PR — the trigger fires for
  any contributor and runs with the base repository's secrets in scope.
- **"CI passes so the action is safe"** does not address mutable refs — a
  compromised upstream can modify the action after CI last passed on a prior run.
- **"The action is from a trusted organisation"** does not eliminate mutable-ref
  risk — a compromised account within that organisation can push to the branch
  the ref points to.
- **"Auto-merge is gated on CI passing"** is a risk reduction, not a full
  mitigation — a supply-chain attack that modifies a dependency to pass CI while
  introducing a backdoor bypasses this control entirely.

## Output Format

For each confirmed finding:

- **[SUP-N]** · SEVERITY · Title
- **Location:** `file:line`
- **Evidence:** quoted config or code snippet
- **Impact:** what an attacker could inject or intercept if this vector is
  exploited (e.g., arbitrary code in CI, poisoned production artifact,
  credential exfiltration)
- **Fix:** specific remediation — pin the ref to a full SHA, add hash
  verification, require a review gate, scope the secret to the consuming step

Group findings by check number. Omit checks that produced no findings.

**File-handoff (when `$OUTPUT_FILE` is set):** Write all findings to the path in
`$OUTPUT_FILE` and return only the following stub to the orchestrator:

```
{
  "domain": "SUP",
  "output_file": "<$OUTPUT_FILE value>",
  "raw_counts": {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N},
  "status": "complete"
}
```

If `$OUTPUT_FILE` is not set, write findings to stdout as usual.

---

## Triage Gate

Before reporting any HIGH or CRITICAL finding, apply the fast-path checks from
`../triage/SKILL.md`. For supply chain findings the most dispositive checks are:

- **Implication/plausibility:** confirm the injected artifact actually reaches
  production (a mutable ref in a never-triggered workflow is LOW, not HIGH)
- **Network reachability:** for pipeline script-fetch findings, confirm the
  fetch target is an external URL, not an internal artifact server that the
  organisation controls
- **Authenticated-admin equivalent access:** if the only actor who can trigger
  the vulnerable workflow already has direct repository write access, the
  marginal risk of the supply chain gap is reduced (MEDIUM, not HIGH)
