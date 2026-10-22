"""Suite definitions shared by the run, score and pairwise commands."""
import hashlib
import json
from pathlib import Path

from . import harness

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
RUNS = ROOT / "runs"
PROMPTS = Path(__file__).parent / "data" / "prompts"

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

# One-line public descriptions of the projects. Written from each project's README tagline,
# not from the advisories or fix commits.
CVE_DESC = {
    "fastjwt": "fast-jwt is a Node.js library to sign, verify and decode JSON Web Tokens.",
    "dmcg": "datamodel-code-generator is a Python tool that generates Python data models from schemas such as OpenAPI, JSON Schema and protobuf.",
    "mariadb": "mariadb-connector-nodejs is the MariaDB client library for Node.js.",
    "strawberry": "Strawberry is a Python GraphQL library with a permission system for resolvers.",
    "ipaddress": "ip-address is a TypeScript library for parsing and manipulating IPv4 and IPv6 addresses.",
    "dulwich": "Dulwich is a pure-Python implementation of Git.",
    "fastify": "@fastify/static is a Fastify plugin that serves static files from a directory.",
    "loofah": "Loofah is a Ruby library for sanitizing and transforming HTML and XML.",
    "commonmark": "league/commonmark is a PHP Markdown parser with an extension system.",
    "pyjwt": "PyJWT is a Python library for encoding and decoding JSON Web Tokens.",
    "kinopenapi": "kin-openapi is a Go library for working with OpenAPI documents and validating HTTP requests against them.",
    "gitpython": "GitPython is a Python library for working with Git repositories.",
    "olivetin": "OliveTin is a web interface that runs predefined shell commands.",
}
CVE_NOTE = (" It is embedded in applications and services that process data from untrusted users or networks."
            " Treat any value that originates from an end user, a remote peer, or a file or archive from outside"
            " the process as attacker-controlled. Configuration set by the developer or operator is trusted.")


def facts_for(suite, repo):
    if suite == "cve":
        return CVE_DESC[repo.split("-")[0]] + CVE_NOTE
    return FACTS[suite]


SUITES = {
    "ssrf": dict(corpus=DATA / "corpus-ssrf", gold=DATA / "gold-ssrf.json", tol=2, gen=None,
                 verifier=PROMPTS / "verifier-ssrf.md"),
    "wide": dict(corpus=DATA / "corpus-wide", gold=DATA / "gold-wide.json", tol=2, gen=WIDE_GEN,
                 verifier=PROMPTS / "verifier-general.md"),
    "mixup": dict(corpus=DATA / "corpus-mixup", gold=DATA / "gold-mixup.json", tol=2, gen=WIDE_GEN,
                  verifier=PROMPTS / "verifier-general.md"),
    "cve": dict(corpus=DATA / "corpus-cve", gold=DATA / "gold-cve.json", tol=5, gen=WIDE_GEN,
                verifier=PROMPTS / "verifier-general.md"),
}


def tree_hash(path):
    h = hashlib.sha1()
    for p in sorted(Path(path).rglob("*")):
        if p.is_file() and ".DS_Store" not in p.name:
            h.update(str(p.relative_to(path)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def config_id(suite, model, skills_dir, guides_dir=None):
    """Hash of everything that can change a run: a changed setting never reuses old records."""
    guides = tree_hash(guides_dir) if guides_dir else ""

    s = SUITES[suite]
    if suite == "cve":
        facts = "\0".join(facts_for(suite, r) for r in sorted(json.loads(s["gold"].read_text())))
    else:
        facts = FACTS.get(suite, "")
    parts = [suite, model, s["gen"] or harness.GEN_PROMPT, facts, s["verifier"].read_text(),
             harness.FINDINGS_SCHEMA, harness.VERDICT_SCHEMA, tree_hash(s["corpus"]), guides,
             tree_hash(skills_dir) if skills_dir else ""]
    return hashlib.sha1("\0".join(parts).encode()).hexdigest()[:8]


def latest_run_dir(suite):
    dirs = sorted(RUNS.glob(f"{suite}-*"), key=lambda d: d.stat().st_mtime)
    return dirs[-1] if dirs else None
