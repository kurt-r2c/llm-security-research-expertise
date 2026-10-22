"""Re-verify existing candidates with a maintainer-supplied facts note (arm +F).

Writes e["verdict_facts"] next to e["verdict"] in each run file. Candidates are not regenerated.
Usage: uv run ablate reverify --suite wide --run-dir runs/wide-...
"""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import harness, suites


def one(args):
    path, suite = args
    r = json.loads(path.read_text())
    if "verify_facts_cost" in r:
        return path.name, "cached"
    cfg = suites.SUITES[suite]
    cwd = harness.stage(cfg["corpus"] / r["repo"])
    tmpl = cfg["verifier"].read_text()
    cost = 0.0
    for e in r["findings"]:
        v, c, _, _ = harness.verify(cwd, e["finding"], r.get("model", "sonnet"), tmpl, facts=suites.facts_for(suite, r["repo"]))
        e["verdict_facts"] = v
        cost += c
    r["verify_facts_cost"] = cost
    path.write_text(json.dumps(r, indent=1))
    return path.name, f"{len(r['findings'])} reverified"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    files = [(p, a.suite) for p in sorted(Path(a.run_dir).glob("*.json"))]
    with ThreadPoolExecutor(a.workers) as ex:
        for name, msg in ex.map(one, files):
            print(name, msg, flush=True)
