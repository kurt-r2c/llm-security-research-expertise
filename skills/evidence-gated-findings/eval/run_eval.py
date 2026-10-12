"""Run arms A (vanilla) and B (skills) over the corpus, then verify every candidate.

Usage: uv run python eval/run_eval.py --skills-dir PATH [--reps 3] [--model sonnet]
Writes eval/runs/<suite>-<config id>/<arm>-<repo>-<rep>.json; the config id hashes the
model, prompts, corpus and skills, so a changed setting never reuses old runs. The gate arms are scored from these files
(same candidates, filtered by verdict), so the only difference is the verifier.
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import harness  # noqa: E402
import suites  # noqa: E402

EVAL = Path(__file__).parent


def one(job):
    arm, repo, rep, model, skills, suite, runs = job
    cfg = suites.SUITES[suite]
    out = runs / f"{arm}-{repo}-{rep}.json"
    cid = suites.config_id(suite, model, skills)
    if out.exists():
        prev = json.loads(out.read_text()).get("config_id")
        if prev and prev != cid:
            raise SystemExit(f"{out}: run was made under config {prev}, current is {cid}; use a new run dir")
        return out.name, "cached" if prev else "cached (legacy, no config id)"
    kw = {"prompt": cfg["gen"]} if cfg["gen"] else {}
    cwd, res, cost, st, trace = harness.generate(
        cfg["corpus"] / repo, model, skills if arm in "BD" else None, expertise=(arm == "C"),
        force_skill=(arm == "D"), facts=suites.facts_for(suite, repo) if arm == "E" else None, **kw)
    rec = {"arm": arm, "repo": repo, "rep": rep, "model": model, "suite": suite, "config_id": cid, "status": st, "gen_cost": cost,
           "trace": trace, "findings": [], "verify_cost": 0.0}
    for f in (res or {}).get("findings", []):
        v, vc, vs, _ = harness.verify(cwd, f, model, cfg["verifier"].read_text())
        rec["verify_cost"] += vc
        rec["findings"].append({"finding": f, "verdict": v, "verdict_status": vs})
    out.write_text(json.dumps(rec, indent=1))
    return out.name, f"{len(rec['findings'])} findings"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--skills-dir", required=True)
    ap.add_argument("--suite", choices=list(suites.SUITES), default="ssrf")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--arms", default="AB", help="subset of A vanilla, B skills available, C guides, D skills forced, E facts note in the generator prompt")
    ap.add_argument("--run-dir", help="reuse a run dir (add arms to existing runs)")
    a = ap.parse_args()
    cfg_id = suites.config_id(a.suite, a.model, a.skills_dir)
    runs = Path(a.run_dir) if a.run_dir else EVAL / "runs" / f"{a.suite}-{a.model}-{cfg_id}"
    runs.mkdir(parents=True, exist_ok=True)
    print("run dir:", runs, flush=True)
    corpus = suites.SUITES[a.suite]["corpus"]
    repos = sorted(p.name for p in corpus.iterdir() if p.is_dir())
    jobs = [(arm, r, i, a.model, a.skills_dir, a.suite, runs)
            for i in range(1, a.reps + 1) for r in repos for arm in a.arms]
    with ThreadPoolExecutor(a.workers) as ex:
        for name, msg in ex.map(one, jobs):
            print(name, msg, flush=True)
