"""Suite definitions shared by run_eval.py and score.py."""
import hashlib
import sys
from pathlib import Path

EVAL = Path(__file__).parent
ROOT = EVAL.parent
sys.path.insert(0, str(ROOT))

WIDE_GEN = (
    "Audit the code in the current directory for security vulnerabilities and logic flaws "
    "an attacker could exploit, including injection, authorization failures and "
    "business-logic errors. Report each candidate finding with file, line, the "
    "attacker-controlled source or precondition, the sink or protected operation, a trace "
    "of file:line steps, and the controls you checked on the path. If there are no "
    "findings return an empty list."
)

SUITES = {
    "ssrf": dict(corpus=EVAL / "corpus", gold=EVAL / "gold.json", tol=2, gen=None,
                 verifier=ROOT / "verifier-prompt.md"),
    "wide": dict(corpus=EVAL / "corpus-wide", gold=EVAL / "gold-wide.json", tol=2, gen=WIDE_GEN,
                 verifier=EVAL / "verifier-prompt-general.md"),
    "mixup": dict(corpus=EVAL / "corpus-mixup", gold=EVAL / "gold-mixup.json", tol=2, gen=WIDE_GEN,
                  verifier=EVAL / "verifier-prompt-general.md"),
}


def tree_hash(path):
    h = hashlib.sha1()
    for p in sorted(Path(path).rglob("*")):
        if p.is_file() and ".DS_Store" not in p.name:
            h.update(str(p.relative_to(path)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def config_id(suite, model, skills_dir):
    import harness

    s = SUITES[suite]
    parts = [suite, model, s["gen"] or harness.GEN_PROMPT, s["verifier"].read_text(),
             harness.FINDINGS_SCHEMA, harness.VERDICT_SCHEMA, tree_hash(s["corpus"]),
             tree_hash(skills_dir) if skills_dir else ""]
    return hashlib.sha1("\0".join(parts).encode()).hexdigest()[:8]


def latest_run_dir(suite):
    dirs = sorted((EVAL / "runs").glob(f"{suite}-*"), key=lambda d: d.stat().st_mtime)
    return dirs[-1] if dirs else None
