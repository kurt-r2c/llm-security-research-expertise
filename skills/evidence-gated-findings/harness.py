"""Generator + independent verifier around `claude -p`. Stdlib only."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
FINDINGS_SCHEMA = (HERE / "schema/findings.schema.json").read_text()
VERDICT_SCHEMA = (HERE / "schema/verdict.schema.json").read_text()
VERIFIER_PROMPT = (HERE / "verifier-prompt.md").read_text()

GEN_PROMPT = """Audit the code in the current directory for server-side request \
forgery (SSRF). Report each candidate finding with file, line, the attacker-controlled \
source, the sink, a trace of file:line steps, and the validation you checked on the \
path. If there are no findings return an empty list."""

BASE = ["claude", "-p", "--setting-sources", "project", "--strict-mcp-config",
        "--no-session-persistence", "--output-format", "json"]


def run_claude(cwd, prompt, schema, tools, model, budget="1.50", skills=False):
    cmd = BASE + ["--model", model, "--json-schema", schema,
                  "--allowedTools", *tools, "--max-budget-usd", budget]
    if not skills:
        cmd.append("--disable-slash-commands")
    p = subprocess.run(cmd + [prompt], cwd=cwd, capture_output=True, text=True, timeout=600)
    try:
        out = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None, 0.0, p.stderr[-300:]
    return out.get("structured_output"), out.get("total_cost_usd", 0.0), out.get("subtype")


def stage(repo, extra_skills=None):
    """Copy a repo to a scratch dir so runs cannot see each other or the gold file."""
    d = Path(tempfile.mkdtemp(prefix="egf-"))
    shutil.copytree(repo, d / "r")
    if extra_skills:
        shutil.copytree(extra_skills, d / "r/.claude/skills")
    return d / "r"


def generate(repo, model, skills_dir=None):
    cwd = stage(repo, skills_dir)
    tools = ["Read", "Grep", "Glob"] + (["Skill"] if skills_dir else [])
    return cwd, *run_claude(cwd, GEN_PROMPT, FINDINGS_SCHEMA, tools, model, skills=bool(skills_dir))


def verify(cwd, finding, model):
    prompt = VERIFIER_PROMPT.replace("{finding}", json.dumps(finding, indent=2))
    return run_claude(cwd, prompt, VERDICT_SCHEMA, ["Read", "Grep", "Glob"], model, budget="0.60")
