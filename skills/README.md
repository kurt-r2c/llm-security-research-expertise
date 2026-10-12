# Skills

Claude Code skills (`SKILL.md` directories) that pair with the guides under `software/`.

| Skill | What it does |
|-------|--------------|
| `security-research/` | Structured security audit: nine domain skills (injection, SSRF, auth, data security, supply chain, agent runtime, infrastructure, output hardening, observability, business logic) plus a `triage` skill applied last. |
| `evidence-gated-findings/` | Gates findings behind an independent read-only verifier. Includes a headless harness and a 13-repo SSRF eval. Result: opt-in, not default; see `evidence-gated-findings/eval/RESULTS.md`. |

To use one, copy the directory into `~/.claude/skills/` or a project's `.claude/skills/`.

Known gap: the domain skills refer to Semgrep rule sets by name (for example `auth_session`).
Those rule sets are not part of this repo. Without them the skills still work from the
checklists alone; the deterministic Semgrep pass is skipped.
