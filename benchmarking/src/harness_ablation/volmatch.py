"""Is a candidate better per finding, or does it just report less (or more)?

Recall rises with the number of findings a run reports, so a harness that changes volume changes recall for a
reason that has nothing to do with judgement. This compares a candidate with the BASELINE DOWNSAMPLED TO THE
CANDIDATE'S VOLUME: for each (repo, rep) of the candidate with n findings, draw n of the baseline's findings for
that repo (pooled over its reps, without replacement) and count the expected hit. If the candidate's recall equals
the volume-matched baseline's, the harness only moved volume; if it is above, it ranks or finds better per finding.
Hit is binary per run (a finding within tol of a fixed site), so this is for suites with one seeded bug per repo.

Usage: uv run ablate volmatch --in haiku:cve:runs/cve-haiku-base --in haiku:cve:runs/cve-haiku-K3 [--base A] [--arm K3]
"""
import argparse
import json
import random
from pathlib import Path

from . import pairwise, score


def hits_of(sc, r):
    return [sc.classify(r["repo"], e["finding"])[0] == "tp" for e in r["findings"]]


def expected_hit(pool, n, rnd, draws=200):
    if n <= 0 or not pool:
        return 0.0
    if n >= len(pool):
        return float(any(pool))
    return sum(any(rnd.sample(pool, n)) for _ in range(draws)) / draws


def compare(base_runs, cand_runs, seed=5):
    """base_runs/cand_runs: list of (repo, rep, [bool hit per finding]) -> per-repo diffs and means."""
    rnd = random.Random(seed)
    pool = {}
    for repo, _, hs in base_runs:
        pool.setdefault(repo, []).extend(hs)
    per = {}
    for repo, _, hs in cand_runs:
        per.setdefault(repo, []).append((float(any(hs)), expected_hit(pool.get(repo, []), len(hs), rnd), len(hs)))
    repos = sorted(per)
    cand = [sum(x[0] for x in per[r]) / len(per[r]) for r in repos]
    matched = [sum(x[1] for x in per[r]) / len(per[r]) for r in repos]
    base = {}
    for repo, _, hs in base_runs:
        base.setdefault(repo, []).append(float(any(hs)))
    basem = [sum(base.get(r, [0])) / len(base.get(r, [0])) for r in repos]
    diffs = [c - m for c, m in zip(cand, matched)]
    return {"n": len(repos), "base": sum(basem) / len(repos), "cand": sum(cand) / len(repos),
            "base_matched": sum(matched) / len(repos), "vs_matched": diffs}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", action="append", required=True, metavar="MODEL:SUITE:RUNDIR")
    ap.add_argument("--base", default="A")
    ap.add_argument("--arm", help="candidate arm (default: every other arm present)")
    a = ap.parse_args(argv)
    by = {}
    for spec in a.inputs:
        model, suite, d = spec.split(":", 2)
        sc = score.Scorer(suite)
        for p in Path(d).glob("*.json"):
            r = json.loads(p.read_text())
            if "advisory" not in sc.gold[r["repo"]]:
                raise SystemExit("volmatch needs a one-bug-per-repo suite (cve)")
            by.setdefault(model, {}).setdefault(r["arm"], []).append((r["repo"], r["rep"], hits_of(sc, r)))
    for model, arms in sorted(by.items()):
        for arm in sorted(arms):
            if arm == a.base or (a.arm and arm != a.arm) or a.base not in arms:
                continue
            c = compare(arms[a.base], arms[arm])
            d = c["vs_matched"]
            lo, hi = pairwise.boot(d)
            print(f"{model} {arm} ({c['n']} repos): recall {c['cand']:.3f}; baseline {c['base']:.3f}; "
                  f"baseline at {arm}'s volume {c['base_matched']:.3f}; {arm} minus volume-matched baseline "
                  f"{sum(d)/len(d):+.3f} [{lo:+.3f}, {hi:+.3f}] sign p {pairwise.sign_p(d):.2f}")


if __name__ == "__main__":
    main()
