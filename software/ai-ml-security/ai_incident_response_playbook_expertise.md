# AI Incident Response Playbook — Expertise

**Audience:** AppSec / Security Engineering lead at an organization that has deployed AI coding tools (Cursor, Claude Code, Cline, Aider, Copilot, Devin) or AI-PR-review platforms (CodeRabbit, Greptile, Cursor BugBot, Semgrep Assistant, Copilot Coding Agent). When one of those tools goes rogue, this is the playbook.

**Register:** Imperative, operational. Do X. Within 15 minutes, do Y. If condition Z, escalate.

**Parent docs:** [[reference-dfir-methodology]] is the general IR substrate; this doc specializes it. [[reference-detection-engineering]] §10 produces the alerts this playbook responds to. [[reference-ai-pr-review-platform]] and [[reference-ai-assisted-coding-tool-security]] describe the threat surfaces; this doc describes what to do when one of those surfaces actually fires. [[reference-cicd-supply-chain]] §2.9 is the canonical anatomy for the Clinejection class worked in §8.

---

## 1. Why AI-IR is a Specialized Class

Classical DFIR ([[reference-dfir-methodology]]) assumes a finite host (machine / container / cloud account), a finite identity (user / service / role), and finite forensic artifacts (memory / disk / network logs). AI-IR violates all three assumptions.

**Different containment levers.** You do not "kill the process." You revoke an MCP allowlist, kill an agent loop, rotate a model-API key at the issuing authority, freeze auto-approve scope, disable scheduled agent runs, and (last resort) network-egress block the model provider. Six new verbs. None of them are in the SANS IR cheat sheet.

**Different forensic surfaces.** The relevant artifacts are not pcap and disk image. They are:

- **Agent session JSONL** (Claude Code: `~/.claude/projects/<encoded-cwd>/<session>.jsonl`; Cursor: per-project conversation logs; Aider: `.aider.chat.history.md`)
- **OpenTelemetry GenAI spans** (`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.tool.name`, `gen_ai.tool.call.arguments`, `gen_ai.usage.*`)
- **MCP tool-call audit logs** (per-server JSONL; usually not on by default)
- **PR comments and commits authored by the agent** — the exfil channel in Comment-and-Control class
- **Model-provider audit logs** (Anthropic Console, OpenAI dashboard, AWS Bedrock CloudTrail data events) with 15-30 minute ingestion lag
- **Host artifacts** (bash_history, process tree, `~/.npm/`, `~/.cache/pip/`, `~/.cargo/registry/`)

None of those surfaces exist for classical malware.

**Different recovery questions.** The killer question that has no classical-DFIR analogue: *was customer data sent to the LLM provider?* If yes, is your contract Zero Data Retention (ZDR)? Does ZDR apply retroactively or only prospectively? Is the provider's audit log retained long enough to confirm? Has the data been used for training? GDPR Article 33 starts a 72-hour clock as soon as you answer "yes" to the first question.

**Different recurrence model.** Classical malware persists via filesystem or registry. AI agents persist via MCP-config mutation (MCPoison class — Check Point Research, August 2025, Cursor keeps trusting an approved MCP config after it is modified), cache poisoning (Cacheract chain in Clinejection — GHSA-9ppg-jx86-fqw7), or settings-file modification (the canonical Claude Code / Cursor write-to-`.claude/settings.json` class). Persistence lives in config you forgot to check.

Classical DFIR is necessary but insufficient. This doc covers the AI-specific delta.

---

## 2. AI-IR Lifecycle — NIST 800-61 Specialized

NIST SP 800-61r2 (Computer Security Incident Handling Guide, superseded by SP 800-61r3 in April 2025) defines four phases (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity), split into six subsections below. Each requires AI-specific specialization.

### 2.1 Preparation

Before any incident, ensure these are in place:

- **MCP allowlist** with sha256-pinned tool versions per [[reference-ai-pr-review-platform]] §12 and [[reference-ai-assisted-coding-tool-security]] §13.
- **OTel GenAI tracing** enabled on every agent runtime; exported to a SIEM or DataDog stream with at least 30-day retention.
- **Model-provider audit logging** enabled — Anthropic Console workspace audit, OpenAI organization-level audit logs, AWS Bedrock model invocation logging (CloudWatch Logs / S3; disabled by default) plus CloudTrail, which records `InvokeModel` as a management event.
- **Vendor IR contact list** populated per §10 of this doc.
- **Tabletop exercises** within 30 days of any new AI tool rollout. Run at least one Clinejection-class scenario and one Comment-and-Control-class scenario.

### 2.2 Detection & Analysis

Alerts come from [[reference-detection-engineering]] §10 (Sigma / KQL / SPL rules for agentic-tool behavior). Common signals:

- Unexpected `npm install` from a forked repo via `claude-code-action` or equivalent agentic bot.
- MCP server configuration file (`~/.cursor/mcp.json`, `~/.claude.json`, `.mcp.json`, `.vscode/mcp.json`) mutated outside an expected change window.
- Agent-authored PR comment containing base64-shaped strings, environment variable names, or URLs to attacker-controlled domains.
- Model-API spend anomaly.
- Bedrock CloudTrail `InvokeModel` with `gen_ai.request.model` mismatched to organization allowlist.

Triage with §5 decision tree.

### 2.3 Containment

See §3 for the lever inventory. The fundamental rule (§7): **if the agent has write capability, contain before forensics.**

### 2.4 Eradication

Eradication is not "delete the binary." It is the sum of:

- MCP-config rollback (verify checksums against pre-incident baseline).
- Cache eviction across all developer hosts and CI runners that may have hit the poisoned cache (Cacheract requires GHA shared cache flush for the affected repository — `gh cache delete --all` per affected repo).
- Model-API key rotation at the issuing authority (Anthropic Console, OpenAI dashboard, AWS IAM for Bedrock).
- Auto-approve allowlist regeneration with reduced scope.
- Scheduled-agent-run audit: re-enable only after each scheduled job is re-reviewed.

The Clinejection post-mortem (`cline.bot/blog/post-mortem-unauthorized-cline-cli-npm`) records a credential-rotation-incompleteness failure: the team rotated through the dashboard but a token remained active until February 17, 2026 exploitation. **Verify rotation by attempting to use the old credential.** If it still works, you have not rotated.

### 2.5 Recovery

- Restore developers to AI tooling only after MCP allowlist is republished and each developer has re-pulled it.
- Re-run the original known-malicious prompt against the patched configuration; if it still succeeds, you have not eradicated.
- Resume scheduled agent runs incrementally — high-trust jobs (release publish) last.
- Communicate to engineering organization. If customer-data exposure (§6) is in scope, route communications through legal counsel first.

### 2.6 Post-Incident

§11 lists the protocol changes. Hold the postmortem within 14 days. Practice blameless framing per [[reference-dfir-methodology]] §11 — the failure mode in AI-IR is almost never "the developer was careless"; it is "the threat model assumed the agent's input was trusted."

---

## 3. Containment Levers Specific to AI-IR

In rough order of escalation. For an active write-capable agent, you will execute most of these in parallel.

### 3.1 Revoke MCP allowlist

The fastest cut. Per-tool commands:

```bash
# Claude Code
claude mcp remove <server-name>
# or, for user-scope servers (stored in ~/.claude.json):
claude mcp remove <server-name> --scope user
# project-scope servers:
mv .mcp.json .mcp.json.quarantine

# Cursor
mv ~/.cursor/mcp.json ~/.cursor/mcp.json.quarantine

# Cline (VSCode)
mv ~/Library/Application\ Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json ~/cline_mcp_settings.json.quarantine  # macOS
```

Cuts the agent's tool-call surface immediately. Does NOT kill an in-flight tool call.

### 3.2 Kill the agent loop

For CLI agents:

```bash
pkill -f 'claude-code|cursor-agent|aider|cline'
```

For agentic GitHub Actions: disable the workflow file:

```bash
gh workflow disable <workflow-name> --repo <org/repo>
```

For Devin / Cursor BugBot / CodeRabbit hosted runners: suspend or uninstall the GitHub App installation at the org level. (`DELETE /app/installations/{installation_id}` must be authenticated with the app's own JWT, so it is not an org-owner command.)

### 3.3 Rotate the model-API key at issuing authority

Do NOT rotate locally. Rotate at the source. The key may be shared across developers, agents, and scheduled jobs:

- **Anthropic:** `console.anthropic.com` → Settings → API Keys → Revoke.
- **OpenAI:** `platform.openai.com/api-keys` → Revoke.
- **AWS Bedrock:** IAM principal credentials — `aws iam delete-access-key` for human users; rotate IAM Role trust policy for service principals.

After revocation, audit how the key was distributed (env vars, Vault, AWS Secrets Manager, GHA encrypted secrets). Every distribution point gets the new key only after the incident is contained.

### 3.4 Freeze auto-approve scope

Reduce the agent's permission surface even while it remains running (if you cannot kill it for evidentiary reasons):

```jsonc
// ~/.claude/settings.json — emergency lockdown
{
  "permissions": {
    "allow": ["Read"],
    "ask": ["*"],
    "deny": ["Bash", "Write", "Edit", "WebFetch", "mcp__*"]
  }
}
```

Equivalent for Cursor: set Auto-Run Mode to "Ask every time" (rules in `.cursor/rules/*.mdc` are prompt guidance, not enforced permissions).

### 3.5 Disable scheduled agent runs

```bash
# GitHub Actions cron triggers
gh workflow list --all | grep -i 'cron\|schedule\|nightly'
# Disable each
gh workflow disable <name> --repo <repo>

# Cline / Cursor scheduled background agents
# Check ~/.cursor/.cursorrules and any "background agents" tab in vendor UI
```

Clinejection's payload was a nightly publish workflow. Scheduled runs are the most overlooked persistence surface.

### 3.6 Network-egress block for model-provider endpoints

Last resort. Cuts all agent activity org-wide. Use only when you cannot identify the compromised key or the compromised agent:

```bash
# At egress proxy / firewall
DENY: api.anthropic.com
DENY: api.openai.com
DENY: bedrock-runtime.*.amazonaws.com
DENY: api.cursor.sh
```

### 3.7 Cache eviction

Cacheract (Clinejection precondition) and prompt-injection-via-cache require flushing:

```bash
# GHA shared cache per repository
gh cache delete --all --repo <org/repo>

# Local developer caches
rm -rf ~/.npm/_cacache
rm -rf ~/.cache/pip
rm -rf ~/.cargo/registry/cache

# Docker BuildKit / buildx cache
docker buildx prune --all --force
```

GitHub's November 20, 2025 cache-eviction change is the Cacheract precondition: once a repository's cache exceeds 10 GB, GitHub now evicts least-recently-used entries immediately instead of every 24 hours, so an attacker can flood the cache to evict legitimate entries and claim their keys with poisoned ones.

### 3.8 Quarantine agent-authored artifacts

Lock the affected repository to prevent further auto-merge:

```bash
gh api -X PATCH /repos/<org>/<repo> -f archived=true
# or, less aggressive:
gh api -X PUT /repos/<org>/<repo>/branches/main/protection -f required_pull_request_reviews.required_approving_review_count=2
```

Review all PR comments and commits authored by the agent within the suspect window before unarchiving.

---

## 4. Forensic Surfaces — What to Collect in Order

Collect in this order. Each is volatile or eventually purged.

### 4.1 Agent session JSONL (immediate; volatile if process is killed)

```bash
# Claude Code — find by working directory
ENCODED_CWD=$(pwd | sed 's|/|-|g')
cp -r ~/.claude/projects/$ENCODED_CWD /secure/ir/$(date +%Y%m%d-%H%M%S)/

# Cursor — per-project
cp -r ~/Library/Application\ Support/Cursor/User/workspaceStorage/ /secure/ir/.../

# Aider — repo-local
cp .aider.chat.history.md /secure/ir/.../
cp .aider.input.history /secure/ir/.../

# Cline — VSCode workspace state
cp -r ~/Library/Application\ Support/Code/User/globalStorage/saoudrizwan.claude-dev/ /secure/ir/.../
```

Captures the agent's tool-call sequence, model responses, and (critically) the original prompt that triggered the compromise.

### 4.2 OTel GenAI spans (5-15 min before SIEM eviction at ingestion-rate-limited tiers)

Query span attributes per the OpenTelemetry GenAI semantic conventions:

- `gen_ai.provider.name` (formerly `gen_ai.system`) — provider (anthropic, openai, aws.bedrock)
- `gen_ai.request.model` — exact model ID
- `gen_ai.tool.name` and `gen_ai.tool.call.arguments` — every tool call the agent made
- `gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens` — sizing the data sent
- `gen_ai.prompt` and `gen_ai.completion` (deprecated and removed from the conventions; content is now recorded via events) — only if your runtime captures these (disabled by default for cost; usually OFF, sometimes ON during incident response)

Pin the time window from first-suspicious-event minus 30 minutes to containment-complete plus 5 minutes. Export to S3 with object-lock for evidentiary integrity.

### 4.3 MCP tool-call audit logs

If MCP audit logging was enabled (recommended baseline per §2.1):

```bash
# Per-MCP-server logs (varies by server implementation)
cp ~/.mcp-audit/*.jsonl /secure/ir/.../
```

If you do not have these logs, log this as a gap in §11.

### 4.4 PR comments and commits authored by the agent (the exfil channel)

Comment-and-Control (Aonan Guan with Johns Hopkins researchers Zhengyu Liu and Gavin Zhong, disclosed April 2026, CVSS 9.4 on the Claude Code Security Review variant) uses PR comments as the exfiltration channel. Capture:

```bash
# All comments by the agent in a window
gh api /repos/<org>/<repo>/issues/comments \
  --paginate \
  --jq '.[] | select(.user.login == "<agent-bot-name>" and .created_at > "<start>" and .created_at < "<end>")' \
  > /secure/ir/.../agent-comments.json

# All commits authored or co-authored by the agent
git log --author='<agent-bot-name>' --since='<start>' --until='<end>' \
  --format='%H %an %ae %s' > /secure/ir/.../agent-commits.txt

# Branches the agent pushed
gh api /repos/<org>/<repo>/branches --paginate \
  --jq '.[] | select(.commit.commit.author.email | test("bot|agent|claude|copilot"))'
```

For each comment, scan for base64-shaped strings, `https://*` to external domains, and environment variable names (`AWS_`, `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, etc).

### 4.5 Model-provider audit logs (15-30 min ingestion lag)

Anthropic: the Compliance API (Enterprise) covers Console admin activity such as member, role, and workspace changes and API key lifecycle events; standalone Console organizations get the Activity Feed only.

OpenAI organization audit: `platform.openai.com/settings/<org>/audit-logs`.

AWS Bedrock: CloudTrail logs `InvokeModel` as a management event. Request/response bodies are captured only by model invocation logging (CloudWatch Logs / S3), which is disabled by default and must be explicitly enabled.

For each, request a vendor data-pull if you suspect exfiltration of customer data — see §6.

### 4.6 Host artifacts

```bash
# Bash history with timestamps
cp ~/.bash_history /secure/ir/.../
cp ~/.zsh_history /secure/ir/.../

# Process tree at moment of capture
ps auxf > /secure/ir/.../ps.txt

# Package manager caches (Cacheract evidence)
find ~/.npm/_cacache -name '*.json' -newer /tmp/incident-start > /secure/ir/.../npm-cache-changes.txt
find ~/.cache/pip -newer /tmp/incident-start > /secure/ir/.../pip-cache-changes.txt
find ~/.cargo/registry -newer /tmp/incident-start > /secure/ir/.../cargo-changes.txt

# Settings files (the persistence surface)
cp -r ~/.claude/ /secure/ir/.../claude-settings/
cp -r ~/.cursor/ /secure/ir/.../cursor-settings/
cp -r .vscode/ /secure/ir/.../workspace-vscode/
```

---

## 5. Triage Decision Tree

Within 5 minutes of alert acknowledgment, walk these questions:

**Q1. Is the agent active right now?**
- YES → contain (§3) BEFORE forensics. Skip to §3.1 and §3.2 immediately.
- NO → proceed to Q2 with forensics-first.

**Q2. Did the agent have write capability?**
- Write to filesystem? Write to repo (commit / PR)? Write to MCP config? Write to cache?
- YES → assume PR comments, commits, config files, and caches are tainted. Quarantine via §3.8.
- NO → likely read-only exposure (less common; EchoLeak is a read-side class).

**Q3. Did the agent have external-network capability via MCP or shell?**
- WebFetch / curl / wget / `npm install <attacker-domain>` / MCP server with network access?
- YES → check §4.4 (PR-comment exfil) and §4.5 (model-provider audit logs) for evidence of egress.
- NO → exfil less likely, but still possible via PR-comment channel.

**Q4. Is the model-API key shared across agents or developers?**
- One key per developer? Per agent? Org-wide shared key?
- SHARED → rotate at issuing authority (§3.3) immediately. Local rotation does not contain.
- ISOLATED → rotation can be deferred until forensic capture completes.

**Q5. Did compromise span multiple sessions?**
- Look for MCP-config mod timestamps (`stat -f %m ~/.claude.json` on macOS, `stat -c %Y ~/.claude.json` on Linux).
- Look for cache modifications (§4.6 `npm-cache-changes.txt`).
- MULTI-SESSION → assume persistent compromise. Eradication (§2.4) must include config + cache + scheduled-job audit.
- SINGLE-SESSION → eradication scope is bounded to the affected developer / runner.

**Q6. Was customer data in scope?**
- Did the agent operate on customer code, customer PII, customer secrets?
- YES → escalate to §6 immediately. GDPR Article 33 72-hour clock may already be running.
- NO → standard internal IR cadence.

---

## 6. "Was Customer Data Sent to the LLM Provider?"

This is the AI-IR-specific question with no classical-DFIR analogue. It has its own subprocess.

### 6.1 Determine what was sent

Reconstruct the input from §4.1 (session JSONL) and §4.2 (OTel spans). Most agent runtimes redact prompts in OTel by default — you may have token-count metadata only. If so, escalate to the model provider per §6.2.

If your runtime captured full prompts (rare; usually OFF for cost), grep the captured prompts for:

- Customer identifiers (customer IDs, account names, tenant slugs)
- Code from customer repos (file paths matching `customer-*`, `tenant-*`)
- Secrets in environment-variable shape
- PII patterns (email, SSN, credit card via standard regex)

### 6.2 Invoke provider IR contact

**Anthropic.** `trust.anthropic.com` → "Contact Security." Request: data-deletion attestation for time window, retention override for forensic preservation, training-confirmation (Anthropic does not train on API inputs by default, but confirm in writing for your account). For active exploitation, mention "active incident response."

**OpenAI.** `trust.openai.com` and `security@openai.com`. Request the same three items. Note: OpenAI's training opt-out is per-organization; verify your org-level setting.

**AWS Bedrock.** `abuse@aws.amazon.com` plus your AWS TAM (Technical Account Manager) if you have one. Bedrock does not train on inputs (model providers operate independently); confirm via your contract. Request CloudTrail data event retention extension if forensic preservation is needed beyond default.

### 6.3 What to ask each provider

Standard request body to all three:

1. Confirmation of data-deletion request for time window `<start>` to `<end>` for API key `<masked-id>`.
2. Confirmation that the inputs were NOT used for model training.
3. Retention override: preserve forensic copies for incident investigation, do not delete on standard schedule.
4. Audit-log data pull for that key in that window.
5. ZDR (Zero Data Retention) attestation if you have a ZDR contract — including whether ZDR applies to inputs already in their system at moment of contract signing (retroactive ZDR is rare).

### 6.4 When to escalate to legal counsel

Trigger conditions:

- **Customer data confirmed exposed** to provider. Notify customers per contract within the timeline specified in your DPA (typically 24-72 hours).
- **Regulated data exposed** (HIPAA PHI, PCI cardholder data, FERPA records). Notify the relevant regulator on the regulator's timeline (HIPAA breach notification: 60 days for >500 individuals; PCI: depends on acquirer contract; FERPA: varies).
- **GDPR personal data exposed.** Article 33: notify supervisory authority within 72 hours of awareness. Article 34: notify affected data subjects if high risk.
- **CCPA personal information exposed.** California AG notification + affected resident notification.

Escalate at the moment you have probable cause to believe customer data was sent. Do NOT wait for confirmation — the 72-hour clock starts at *awareness*, not at *confirmation*.

---

## 7. Containment-vs-Eradication Trade-off

The unique AI-IR trade-off: containment discards forensic evidence; observation preserves it but allows compromise to continue.

**Containment cost.** Killing the agent loop (§3.2) discards in-flight tool-call results, working memory, and the active context window. You lose the smoking gun.

**Observation cost.** Letting the agent continue means it may make more tool calls, exfil more data, taint more artifacts. Each additional second of observation is additional damage.

**Rule.** For any agent with WRITE capability (filesystem, repo, network egress), **containment wins**. Forensics will be incomplete but recoverable from §4.1 (JSONL) and §4.2 (OTel). For read-only agents in a sandbox with no egress, observation acceptable up to 5 minutes — long enough to capture the prompt and full tool-call sequence, short enough to limit blast radius if your "read-only" assumption is wrong.

**Clinejection eradication-incompleteness lesson.** The post-mortem (`cline.bot/blog/post-mortem-unauthorized-cline-cli-npm`) records that credential rotation was incomplete: rotated through the dashboard but a token remained active until February 17, 2026 exploitation. **Eradication-incomplete is the more common failure mode than over-eager containment.** Verify rotation by attempting old credential. Verify cache eviction by re-running the trigger. Verify config rollback by checksum.

---

## 8. Worked Example 1: Clinejection-Class Anatomy

Source: `adnanthekhan.com/posts/clinejection/`, GHSA-9ppg-jx86-fqw7 (published February 17, 2026), `cline.bot/blog/post-mortem-unauthorized-cline-cli-npm`. See [[reference-cicd-supply-chain]] §2.9 for full structural analysis.

### Timeline

**T+0.** Attacker opens issue on public repo with title containing prompt-injection payload. Trigger: GitHub Actions `issues` event with `allowed_non_write_users: "*"` on `claude-code-action`.

**T+5min.** `claude-code-action` workflow fires. Agent ingests issue title. Prompt injection lands.

**T+6min.** Agent executes `npm install` from attacker fork.

  → **Detection rule fires** ([[reference-detection-engineering]] §10): `gh_action_npm_install_from_fork` — sigma rule matching `gen_ai.tool.arguments` containing `npm install` with a non-organization registry origin.

  → **Containment lever §3.1** (revoke MCP allowlist) does not help here — the attack is via shell, not MCP.

  → **Containment lever §3.2** (kill agent loop) and **§3.5** (disable scheduled runs) are the right cuts. Also disable the workflow file: `gh workflow disable claude-code-action`.

  → **Forensic capture §4.1** — Claude Code session JSONL is on the GHA runner. Runner is ephemeral; you have minutes before it terminates. Use the workflow's artifact-upload step to capture if you wired one in §2.1.

**T+7min.** Cacheract poisons the GHA shared cache for the repository.

  → **Detection rule fires**: `gh_cache_write_from_npm_postinstall` — sigma rule on cache-write paths matching node_modules-adjacent.

  → **Containment §3.7** — `gh cache delete --all --repo <repo>` immediately.

**T+next-night.** Nightly publish workflow runs. Reads from poisoned cache. Exposes the npm publish token (`NPM_RELEASE_TOKEN`). Publishes `cline@2.3.0` with an unauthorized `postinstall` (`postinstall: npm install -g openclaw@latest`).

  → **Detection rule fires**: `npm_publish_unexpected_token_usage` — anomaly on `pushed_at` against publish-token last-used.

  → **Forensic §4.5** — npm-side audit logs from npmjs.com for the publish token.

### Real outcome

GHSA-9ppg-jx86-fqw7 published February 17, 2026, severity "low" because the payload was only a postinstall instruction (no active malware in-package). Cline team's post-mortem cited rotation incompleteness as the compounding failure: credential rotated through dashboard but token remained active until February 17 exploitation.

**Right choices Cline made:** published post-mortem with structural framing.

**Wrong choices:** did not verify rotation by attempting old credential; did not audit the `claude-code-action` `allowed_non_write_users: "*"` setting before adopting; assumed the trigger (`issues` event) was incidental rather than structural.

---

## 9. Worked Example 2: Comment-and-Control on Claude Code Security Review

Source: Aonan Guan with Johns Hopkins researchers Zhengyu Liu and Gavin Zhong, disclosed April 2026. CVSS 9.4 on the Claude Code Security Review variant. Affected: Anthropic Claude Code Security Review, Gemini CLI Action, Copilot Agent. See [[reference-ai-pr-review-platform]] §10 for full anatomy.

### Timeline

**T+0.** Attacker opens PR against target repo. PR title contains prompt-injection payload directing the AI reviewer to (a) execute attacker tools, (b) write a comment containing credentials from environment, (c) approve the PR.

**T+1min.** Reviewer (Claude Code Security Review) ingests PR title and diff. Prompt injection lands inside the reviewer's context.

  → **Detection rule fires** ([[reference-detection-engineering]] §10): `pr_title_prompt_injection_shape` — sigma rule on PR title matching prompt-injection patterns (long base64, "ignore previous instructions" variants, role-confusion markers).

  → **Containment §3.4** (freeze auto-approve) is the right early cut. Force the reviewer to ask-mode for the affected repository.

**T+2min.** Reviewer executes attacker-specified tools. Writes credential-bearing comment on the PR.

  → **Detection rule fires**: `agent_pr_comment_high_entropy_string` — Shannon entropy on agent-authored comments; anomaly on environment-variable names appearing in comment body.

  → **Containment §3.8** (quarantine agent-authored artifacts) — archive the PR; lock the repo branch protection to require human approval.

  → **Forensic §4.4** — capture the exfil comment before it's deleted. `gh api /repos/<org>/<repo>/issues/comments/<id>` and snapshot.

  → **Forensic §4.5** — Anthropic Console audit log; correlate with comment-write timestamp.

**T+15min.** AppSec engineer notified via Sigma alert. Walks §5 decision tree.

  → Q1: agent likely no longer active (PR review completes in <2 min).
  → Q2: write capability YES (PR comments, possibly commits).
  → Q3: external-network via MCP — depends on configuration.
  → Q4: shared model-API key YES (single API key per organization is typical for AI-PR-review platforms).
  → Q5: scope to one PR; not yet multi-session.
  → Q6: depends on what credentials were in environment.

### Real outcome

Anthropic rated it CVSS 9.4 (reported via HackerOne, $100 bounty) and shipped partial mitigations, including disallowing the `ps` tool; the researcher reports the attack still works in principle. Google added guardrail prompts to Gemini CLI Action; GitHub classified the Copilot Agent issue as a known architectural limitation.

**Generalization.** Any AI-PR-review platform with PR-comment write capability and credentialed environment is vulnerable to this class. Not unique to Claude Code Security Review — affected Gemini CLI Action and GitHub Copilot Agent.

---

## 10. Vendor-Coordination Protocols

Per-provider contact and disclosure norms.

### 10.1 Anthropic

**Trust portal:** `trust.anthropic.com`
**Security disclosure:** `anthropic.com/responsible-disclosure-policy` (HackerOne program)
**What they need:** API key prefix (masked), time window (UTC), model ID, tool names if available, sample of malicious input.
**Disclosure timing:** coordinate timing with Anthropic (the policy states no fixed window).

### 10.2 OpenAI

**Trust portal:** `trust.openai.com`
**Security disclosure:** `openai.com/security` (Bugcrowd program)
**Direct:** `security@openai.com`
**What they need:** Organization ID, API key prefix, time window, model, sample input.
**Disclosure timing:** 90 days standard.

### 10.3 AWS Bedrock

**Direct:** `abuse@aws.amazon.com` and `aws-security@amazon.com`
**Plus:** your Technical Account Manager (TAM) if you have one.
**SLA:** depends on Support tier; Enterprise Support targets 15 minutes for business-critical system down and 1 hour for production system down.
**What they need:** AWS account ID, region, IAM principal ARN, CloudTrail event IDs if available, time window.

### 10.4 GitHub

**Direct:** `security@github.com` (also `github.com/security`)
**For Copilot specifically:** include "GitHub Copilot" in subject.
**What they need:** repository (if public, link; if private, scoped access discussion), workflow names, action runner IDs if available.
**Disclosure timing:** 90 days standard via GitHub Security Advisories.

### 10.5 Microsoft (Copilot for M365, Azure OpenAI)

**MSRC:** `msrc.microsoft.com/report` or `secure@microsoft.com`
**Bounty:** the Microsoft Copilot (AI) Bounty Program covers consumer Copilot; Copilot-related online services such as M365 Copilot fall under the M365 Bounty Program.
**What they need:** tenant ID, time window, affected service, sample input.

### 10.6 Coordinated-disclosure norms

90-day disclosure is the default. Active exploitation (in-the-wild incident) compresses the timeline — vendors typically commit to a fix within 7-30 days for active exploitation, with public disclosure following the fix. Examples: CurXecute (CVE-2025-54135, Aim Labs disclosure to Cursor August 2025), EchoLeak (CVE-2025-32711, Aim Labs disclosure to Microsoft June 2025), PwnedRabbit (Kudelski Security Research disclosure to CodeRabbit January 2025, published August 2025), ShadowLeak (Radware disclosure to OpenAI, fix September 3, 2025), MCPoison (Check Point disclosure to Cursor August 2025).

---

## 11. Post-Incident Protocol Changes

After every AI-IR incident, ship the following before closing the postmortem.

### 11.1 New detection rules

Extend [[reference-detection-engineering]] §10 with:

- Sigma rule matching the specific prompt-injection shape that triggered the incident.
- KQL or SPL rule on the OTel span pattern that produced the alert.
- Anomaly rule on the model-API spend signature (token volume, model ID, time-of-day).

Commit to the detection-rules repo with PR reviewed by AppSec + Detection Engineering.

### 11.2 MCP allowlist tightening

Add the specific MCP server to a deny-list with sha256-pin OR remove the entire server from allowlist:

```jsonc
// .mcp.json (project-scope template)
{
  "mcpServers": {
    "approved-server-name": {
      "command": "npx",
      "args": ["@scope/package@1.2.3"]
    }
  }
}
```

Republish to all developers via your MDM or onboarding tooling.

### 11.3 Auto-approve scope reduction

Move tools that were auto-approved at incident time into ask-mode:

```jsonc
{
  "permissions": {
    "allow": [...],
    "ask": ["WebFetch", "Bash(npm:*)", "mcp__*"],
    "deny": ["Bash(curl:*)", "Bash(wget:*)"]
  }
}
```

### 11.4 Vendor diligence checklist additions

Update [[reference-ai-pr-review-platform]] §12 with any new diligence question surfaced by the incident. Common additions: "Does the platform write PR comments? If yes, how is comment content scanned for exfil shapes?"; "Does the platform allow per-customer MCP allowlists? If no, can it be self-hosted?"

### 11.5 Tabletop exercise

Run a tabletop within 30 days of incident close, using the actual incident as the scenario. Invite: AppSec, Detection Engineering, IR on-call rotation, Engineering leadership. Output: confirmed playbook fits new scenario OR playbook updates.

### 11.6 Quarterly cadence

Quarterly AI-IR tabletop. Rotate scenarios: Clinejection-class (T+next-night supply-chain), Comment-and-Control class (T+2min exfil), CurXecute-class (T+5min token-spend anomaly), EchoLeak-class (read-side exfil with no obvious exfil channel).

---

## 12. 12-Item AppSec-Lead Playbook Checklist

For an active incident, in order. Estimated wallclock to complete each step in parentheses.

1. **Confirm alert is real.** (2 min) Look at the triggering detection rule output. Cross-check with §4.2 OTel spans. False-positive rate on AI-tool alerts is non-trivial; do not waste an on-call rotation on a hallucination.

2. **Page on-call.** (1 min) IR on-call rotation. If customer data may be in scope, page legal counsel concurrently.

3. **Containment.** (5-15 min) Walk §3 in order. Revoke MCP allowlist → kill agent loop → rotate model-API key → freeze auto-approve → disable scheduled runs. Network-egress block only if you cannot identify the compromised key.

4. **Forensic capture.** (15-30 min) Walk §4 in order. Session JSONL → OTel spans → MCP audit logs → PR comments → provider audit logs → host artifacts.

5. **Customer-data exposure check.** (30 min) Walk §6.1 to determine what was sent. If non-zero customer data in scope, invoke §6.2 vendor IR contact and §6.4 legal counsel.

6. **Vendor IR contact.** (15 min) Open ticket with model provider per §10. If multiple providers involved (Bedrock-hosted Anthropic, for example), open with each separately.

7. **Communicate to engineering.** (variable; AFTER legal sign-off if §6 customer-data exposure is in scope) Email or Slack to engineering org. Include: scope, containment status, expected developer impact, when AI tools will be re-enabled.

8. **Eradicate.** (1-4 hours) Walk §2.4. MCP-config rollback with checksum verification → cache eviction across all hosts and CI runners → model-API key rotation verified by attempting old credential → auto-approve allowlist regeneration → scheduled-job audit.

9. **Verify.** (15-30 min) Re-run the original known-malicious prompt against the patched configuration. If it still succeeds, eradication is incomplete; return to step 8.

10. **Recover.** (variable; hours to days depending on scope) Restore developers to AI tooling incrementally. High-trust scheduled jobs (release publish) last. Communicate restoration timeline to engineering.

11. **Postmortem.** (within 14 days) Blameless framing per [[reference-dfir-methodology]] §11. Surface the structural failure, not the human one. Distribute internally; consider public post-mortem if disclosure benefits the community (Cline did this; pattern worth following).

12. **Ship protocol changes.** (within 30 days) Walk §11. New detection rules → MCP allowlist tightening → auto-approve scope reduction → vendor diligence checklist additions → tabletop exercise → updated quarterly cadence.

---

## 13. Cross-Link Cluster + Known Gaps

### Cross-links

- **[[reference-dfir-methodology]]** — parent doc; NIST 800-61 lifecycle, memory/disk/network forensics, blameless postmortem discipline.
- **[[reference-cicd-supply-chain]]** §2.9 — Clinejection canonical anatomy. AI-CI threat model framing: structural triple of (untrusted text + agent tool access + privileged context).
- **[[reference-ai-pr-review-platform]]** — PwnedRabbit + Comment-and-Control anatomies. §12 vendor-diligence checklist that §11.4 extends.
- **[[reference-ai-assisted-coding-tool-security]]** — IDE-side AI tool class. §13 Semgrep policy. §14 worked-example hardening (devcontainer, settings.json, MCP allowlist, audit-logging, egress proxy).
- **[[reference-detection-engineering]]** §10 — Sigma/KQL/SPL rules that produce the alerts this playbook responds to. §11 ships new rules back into.

### Known gaps

- **Per-vendor IR contact details drift.** §10 captures May 2026 state. URLs and SLAs may change. Verify before incident.
- **Mobile AI-tool incidents not covered.** Mobile-side prompt-injection and agent compromise are emerging but no canonical incidents yet. Cross-link [[reference-mobile-security]] when corpus develops.
- **On-prem and air-gapped deployments not covered.** Ollama, LM Studio, vLLM, and llama.cpp deployments have different forensic surfaces (no provider audit log; no provider IR contact). Future deepening target.
- **Cyber-insurance angle flagged for future.** Coverage for AI-IR incidents is nascent; policy language varies; claims process for "AI tool exfiltrated customer data" is untested. Cross-link [[reference-game-theory-mechanism-design]] (cyber-insurance adverse selection + moral hazard).
- **Provider-side detection capabilities are evolving.** Anthropic, OpenAI, and AWS are each shipping internal-side detection for prompt-injection patterns; the customer-side detection in [[reference-detection-engineering]] §10 is the current necessary substrate but may become less critical as provider-side detection matures.
- **MCP audit logging defaults vary by server.** Recommendation to enable is §2.1 baseline; vendor adoption is uneven.

### Real-incident anchor index

- **Clinejection** GHSA-9ppg-jx86-fqw7 (Adnan Khan, `adnanthekhan.com/posts/clinejection/`, published February 9, 2026) — §8 worked example.
- **Comment-and-Control** (Aonan Guan with Johns Hopkins researchers Zhengyu Liu and Gavin Zhong, disclosed April 2026, CVSS 9.4 on Claude Code Security Review variant) — §9 worked example.
- **PwnedRabbit** (Kudelski Security Research disclosed January 2025 / published August 2025, CodeRabbit RCE via un-sandboxed Rubocop → GitHub App PEM exfil → write access to 1M repos) — §10.6 disclosure-timeline anchor.
- **CurXecute** CVE-2025-54135 (Aim Labs disclosure to Cursor, August 2025) — §2.2 token-spend anomaly anchor.
- **EchoLeak** CVE-2025-32711 (Aim Labs disclosure to Microsoft M365 Copilot, June 2025) — §11.6 tabletop scenario anchor.
- **MCPoison** (Check Point Research disclosure to Cursor, August 2025) — §1 persistence-via-config anchor.
- **ShadowLeak** (Radware disclosure to OpenAI ChatGPT Deep Research, fix September 3, 2025) — §10.6 disclosure-timeline anchor.
- **CVE-2025-53773** (Johann Rehberger / Embrace The Red, GitHub Copilot RCE via prompt injection) — §9 Comment-and-Control generalization anchor.
