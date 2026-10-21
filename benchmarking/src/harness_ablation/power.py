"""Power and minimum-detectable-effect for the repo-level decision rule, simulated from pilot runs.

Takes the baseline arm of a pilot (any suite or mix of suites), treats each repo's baseline hit rate
as its true rate, then asks: if the candidate recovered `delta` of pooled recall, how often would the
rule (bootstrap CI above 0 AND exact sign p below alpha) say so with N repos and R reps? A pilot with
many repos that are always missed (or always found) carries little information; the report says how
many repos are informative. Gold with several seeded bugs per repo is simulated as one binary hit.

Usage: uv run ablate power --in sonnet:cve:runs/cve-sonnet-base [--base A] [--repos 17,30,50,80]
                           [--deltas 0.05,0.1,0.15,0.2] [--reps 2] [--tests 6] [--sims 400]
"""
import argparse
import random

from . import pairwise, verdict


def base_rates(runs):
    per = {}
    for (repo, _), v in runs.items():
        if v["gold"]:
            per.setdefault(repo, []).append(min(v["found"], v["gold"]) / v["gold"])
    return {r: sum(x) / len(x) for r, x in per.items()}


def passes(diffs, alpha, rnd, nboot=300):
    nz = [d for d in diffs if d]
    if not nz:
        return False
    boots = sorted(sum(rnd.choices(diffs, k=len(diffs))) / len(diffs) for _ in range(nboot))
    return boots[int(0.025 * nboot)] > 0 and pairwise.sign_p(diffs) < alpha


def simulate(rates, n_repos, reps, delta, alpha, sims, seed=7):
    rnd = random.Random(seed)
    mean_p = sum(rates) / len(rates)
    g = min(1.0, delta / (1 - mean_p)) if mean_p < 1 else 0.0
    hit = 0
    for _ in range(sims):
        diffs = []
        for p in rnd.choices(rates, k=n_repos):
            q = p + g * (1 - p)
            a = sum(rnd.random() < p for _ in range(reps))
            b = sum(rnd.random() < q for _ in range(reps))
            diffs.append((b - a) / reps)
        hit += passes(diffs, alpha, rnd)
    return hit / sims


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", action="append", required=True, metavar="MODEL:SUITE:RUNDIR")
    ap.add_argument("--base", default="A")
    ap.add_argument("--repos", default="17,30,50,80")
    ap.add_argument("--deltas", default="0.05,0.10,0.15,0.20")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--tests", type=int, default=1, help="number of tests in the family (Bonferroni alpha/tests)")
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--sims", type=int, default=400)
    a = ap.parse_args(argv)
    data = verdict.load(a.inputs)
    for model, arms in data.items():
        rates = base_rates(arms[a.base])
        vals = list(rates.values())
        mid = sum(0 < v < 1 for v in vals)
        print(f"## {model}: {len(vals)} pilot repos, baseline recall {sum(vals)/len(vals):.3f}, "
              f"always missed {sum(v == 0 for v in vals)}, always found {sum(v == 1 for v in vals)}, informative {mid}")
        ns, ds = [int(x) for x in a.repos.split(",")], [float(x) for x in a.deltas.split(",")]
        print(f"power, reps={a.reps}, alpha={a.alpha}/{a.tests} (rows: repos; columns: pooled recall gain)")
        print("repos  " + "".join(f"{d:>8.2f}" for d in ds) + "   MDE@80%")
        for n in ns:
            pw = [simulate(vals, n, a.reps, d, a.alpha / a.tests, a.sims) for d in ds]
            mde = next((d for d, p in zip(ds, pw) if p >= 0.8), None)
            print(f"{n:5d}  " + "".join(f"{p:8.2f}" for p in pw) + f"   {'>' + str(ds[-1]) if mde is None else mde}")


if __name__ == "__main__":
    main()
