# Skills

Agent skills (`SKILL.md` directories) that pair with the guides under `software/`.

| Skill | What it does |
|-------|--------------|
| `security-research/` | Structured security audit: nine domain skills (injection, SSRF, auth, data security, supply chain, agent runtime, infrastructure, output hardening, observability, business logic) plus a `triage` skill applied last. |
| `root-cause-fanout/` | Decomposes a CVE reported against a product down to the single-purpose component that broke (decoder, parser, codec), then fans out to every consumer by inheritance mechanism, every other implementation (ports of a reference implementation first), and every side effect and input direction. Worked example: the October 2026 Brotli decoder bug. |
| `evidence-gated-findings/` | Gates findings behind an independent read-only verifier. Includes a headless harness and a 13-repo SSRF eval. Result: opt-in, not default; see `evidence-gated-findings/eval/RESULTS.md`. |

## Install

From the repo root:

```bash
make detect     # which agent runtimes are present, and which skills roots they read
make install    # install every skill into each detected root
make status     # what is installed where, and any name clashes
make update     # git pull --ff-only, then reinstall
make uninstall  # remove only what `make install` put there
```

A runtime counts as present when its binary is on `PATH`, its config directory exists, or its macOS
app is installed. Roots:

| Runtime | Skills root |
|---------|-------------|
| Claude Code | `~/.claude/skills` |
| Cursor | `~/.cursor/skills` |
| Codex, Copilot CLI, Gemini CLI, Goose, OpenCode | `~/.agents/skills` (the shared cross-agent location) |
| Windsurf | `~/.codeium/windsurf/skills` |
| OpenClaw | `~/.openclaw/skills` |

Any of the roots above that already holds a `*/SKILL.md` is included even if no runtime was
detected. `ROOTS="dir ..."` skips detection, for example `ROOTS=.claude/skills` for a project install.

- Skills install under their frontmatter `name` (`security-research/` installs as
  `security-research-audit/`), since OpenCode and Goose require the directory to match.
- Copy mode (the default) installs every file git does not ignore, so no virtualenvs or eval runs,
  and leaves out the deliberately vulnerable `eval/corpus*` fixtures. `MODE=link` symlinks to this checkout instead, so `git pull` alone updates.
- Each copy carries a `.installed-by-llm-security-research-expertise` marker. Install, update and
  uninstall only replace or remove directories with that marker, or symlinks into this repo.
  A directory that isn't ours, or another skill declaring the same `name`, is skipped unless
  `FORCE=1`. `DRY_RUN=1` prints the plan.
- Some runtimes read several roots (Copilot and OpenCode also read `~/.claude/skills`), so they
  may list a skill twice. Use `ROOTS` to pick one.
- The `evidence-gated-findings` Stop hook is installed with the skill but not registered; see its
  `SKILL.md`, step 4.

Known gap: the domain skills refer to Semgrep rule sets by name (for example `auth_session`).
Those rule sets are not part of this repo. Without them the skills still work from the
checklists alone; the deterministic Semgrep pass is skipped.
