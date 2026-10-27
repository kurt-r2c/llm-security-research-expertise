"""Generator + independent verifier around `claude -p`. Stdlib only."""
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
EXPERTISE_KB = HERE.parent.parent / "knowledge-base"
FINDINGS_SCHEMA = (HERE / "schema/findings.schema.json").read_text()
VERDICT_SCHEMA = (HERE / "schema/verdict.schema.json").read_text()
VERIFIER_PROMPT = (HERE / "verifier-prompt.md").read_text()

GEN_PROMPT = """Audit the code in the current directory for server-side request \
forgery (SSRF). Report each candidate finding with file, line, the attacker-controlled \
source, the sink, a trace of file:line steps, and the validation you checked on the \
path. If there are no findings return an empty list."""

BASE = ["claude", "-p", "--setting-sources", "project", "--strict-mcp-config",
        "--no-session-persistence", "--output-format", "stream-json", "--verbose"]


def run_claude(cwd, prompt, schema, tools, model, budget="1.50", skills=False, add_dirs=()):
    """Returns (structured_output, cost_usd, subtype, trace). trace = tool-use counts + Skill names."""
    cmd = BASE + ["--model", model, "--json-schema", schema,
                  "--allowedTools", *tools, "--disallowedTools", "Bash", "--max-budget-usd", budget]
    for d in add_dirs:
        cmd += ["--add-dir", str(d)]
    if not skills:
        cmd.append("--disable-slash-commands")
    p = subprocess.run(cmd + [prompt], cwd=cwd, capture_output=True, text=True, timeout=900)
    trace = {"tools": {}, "skills": [], "reads": []}
    out = {}
    for line in p.stdout.splitlines():
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if o.get("type") == "assistant":
            for b in o["message"]["content"]:
                if b.get("type") != "tool_use":
                    continue
                trace["tools"][b["name"]] = trace["tools"].get(b["name"], 0) + 1
                if b["name"] == "Skill":
                    trace["skills"].append(b["input"].get("skill"))
                if b["name"] == "Read":
                    trace["reads"].append(b["input"].get("file_path", ""))
        elif o.get("type") == "result":
            out = o
    if not out:
        return None, 0.0, p.stderr[-300:], trace
    return out.get("structured_output"), out.get("total_cost_usd", 0.0), out.get("subtype"), trace


def stage(repo, extra_skills=None, expertise=False):
    """Copy a repo to a scratch dir so runs cannot see each other or the gold file."""
    d = Path(tempfile.mkdtemp(prefix="egf-"))
    shutil.copytree(repo, d / "r")
    if extra_skills:
        shutil.copytree(extra_skills, d / "r/.claude/skills")
    if expertise:
        (d / "expertise").mkdir()
        shutil.copy(HERE / "eval/expertise-INDEX.md", d / "expertise/INDEX.md")
        (d / "expertise/knowledge-base").symlink_to(EXPERTISE_KB)
    return d / "r"


FACTS_PREFIX = "Project facts (supplied by the maintainer; treat as true):\n{facts}\n\n"

C_SUFFIX = (" Reference guides on vulnerability classes and language-specific pitfalls are in "
            "{path} (start with INDEX.md). Read the ones relevant to this code before reporting.")


D_SUFFIX = " Use the security-research skill (Skill tool) for this audit and follow its procedure."


def generate(repo, model, skills_dir=None, prompt=GEN_PROMPT, expertise=False, force_skill=False, facts=None):
    cwd = stage(repo, skills_dir, expertise)
    tools = ["Read", "Grep", "Glob"] + (["Skill"] if skills_dir else [])
    add = []
    if facts:
        prompt = FACTS_PREFIX.format(facts=facts) + prompt
    if force_skill:
        prompt += D_SUFFIX
    if expertise:
        prompt += C_SUFFIX.format(path=cwd.parent / "expertise")
        add = [cwd.parent / "expertise"]
    return (cwd, *run_claude(cwd, prompt, FINDINGS_SCHEMA, tools, model,
                             skills=bool(skills_dir), add_dirs=add))


def verify(cwd, finding, model, template=VERIFIER_PROMPT, facts=None):
    prompt = template.replace("{finding}", json.dumps(finding, indent=2))
    if facts:
        prompt = FACTS_PREFIX.format(facts=facts) + prompt
    return run_claude(cwd, prompt, VERDICT_SCHEMA, ["Read", "Grep", "Glob"], model, budget="0.60")
