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

FACTS = {
    "wide": (
        "Each directory is one module of a larger web application. Request identity "
        "(g.user, req.user, session user, context user) is populated by trusted upstream "
        "middleware that is not part of this directory. Every route or handler shown is "
        "reachable by an HTTP client unless a decorator or check in the code restricts it. "
        "Functions with no caller here are called by the rest of the application."
    ),
}
FACTS["mixup"] = FACTS["wide"]

SUITES = {
    "ssrf": dict(corpus=EVAL / "corpus", gold=EVAL / "gold.json", tol=2, gen=None,
                 verifier=ROOT / "verifier-prompt.md"),
    "wide": dict(corpus=EVAL / "corpus-wide", gold=EVAL / "gold-wide.json", tol=2, gen=WIDE_GEN,
                 verifier=EVAL / "verifier-prompt-general.md"),
    "mixup": dict(corpus=EVAL / "corpus-mixup", gold=EVAL / "gold-mixup.json", tol=2, gen=WIDE_GEN,
                  verifier=EVAL / "verifier-prompt-general.md"),
    "cve": dict(corpus=EVAL / "corpus-cve", gold=EVAL / "gold-cve.json", tol=5, gen=WIDE_GEN,
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

    guides = tree_hash(ROOT.parent.parent / "software") + (EVAL / "expertise-INDEX.md").read_text()

    s = SUITES[suite]
    parts = [suite, model, s["gen"] or harness.GEN_PROMPT, s["verifier"].read_text(),
             harness.FINDINGS_SCHEMA, harness.VERDICT_SCHEMA, tree_hash(s["corpus"]), guides,
             tree_hash(skills_dir) if skills_dir else ""]
    return hashlib.sha1("\0".join(parts).encode()).hexdigest()[:8]


def latest_run_dir(suite):
    dirs = sorted((EVAL / "runs").glob(f"{suite}-*"), key=lambda d: d.stat().st_mtime)
    return dirs[-1] if dirs else None
