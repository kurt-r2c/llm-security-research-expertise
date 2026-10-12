"""Run arms A (vanilla) and B (skills) over the corpus, then verify every candidate.

Usage: uv run python eval/run_eval.py --skills-dir PATH [--reps 3] [--model sonnet]
Writes eval/runs/<arm>-<repo>-<rep>.json. The gate arms are scored from these files
(same candidates, filtered by verdict), so the only difference is the verifier.
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import harness  # noqa: E402

EVAL = Path(__file__).parent
CORPUS = EVAL / "corpus"
RUNS = EVAL / "runs"


def one(job):
    arm, repo, rep, model, skills = job
    out = RUNS / f"{arm}-{repo}-{rep}.json"
    if out.exists():
        return out.name, "cached"
    cwd, res, cost, st = harness.generate(CORPUS / repo, model, skills if arm == "B" else None)
    rec = {"arm": arm, "repo": repo, "rep": rep, "status": st, "gen_cost": cost,
           "findings": [], "verify_cost": 0.0}
    for f in (res or {}).get("findings", []):
        v, vc, vs = harness.verify(cwd, f, model)
        rec["verify_cost"] += vc
        rec["findings"].append({"finding": f, "verdict": v, "verdict_status": vs})
    out.write_text(json.dumps(rec, indent=1))
    return out.name, f"{len(rec['findings'])} findings"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--skills-dir", required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    RUNS.mkdir(exist_ok=True)
    repos = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())
    jobs = [(arm, r, i, a.model, a.skills_dir) for i in range(1, a.reps + 1) for r in repos for arm in "AB"]
    with ThreadPoolExecutor(a.workers) as ex:
        for name, msg in ex.map(one, jobs):
            print(name, msg, flush=True)
