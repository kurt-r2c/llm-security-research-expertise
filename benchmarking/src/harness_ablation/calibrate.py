"""A/A calibration: how often does the decision rule declare a winner when nothing differs?

Within each repo the reps of ONE arm are split at random into two pseudo-arms (so the null is true by
construction, the run noise and repo mix are real), and the rule is applied. The share of splits that
"pass" is the empirical false-KEEP rate of the procedure on your data, to compare with the nominal
alpha. Optionally compares two real runs of the same arm made at different times (drift check).

Usage: uv run ablate calibrate --in sonnet:cve:runs/cve-sonnet-base [--arm A] [--sims 2000]
                               [--other sonnet:cve:OLD_RUN_DIR]   # arm A of an older session
"""
import argparse
import json
import random
from pathlib import Path

from . import pairwise, verdict


def split_diffs(runs, rnd):
    per = {}
    for (repo, rep), v in runs.items():
        if v["gold"]:
            per.setdefault(repo, []).append(min(v["found"], v["gold"]) / v["gold"])
    diffs = []
    for vals in per.values():
        if len(vals) < 2:
            continue
        rnd.shuffle(vals)
        h = len(vals) // 2
        diffs.append(sum(vals[:h]) / h - sum(vals[h:]) / (len(vals) - h))
    return diffs


def rates(runs, sims, alpha, seed=11):
    rnd = random.Random(seed)
    sign = ci = both = 0
    for _ in range(sims):
        d = split_diffs(runs, rnd)
        s = bool(any(d)) and pairwise.sign_p(d) < alpha
        lo, hi = pairwise.boot(d, n=300, seed=rnd.randrange(10**6)) if any(d) else (0, 0)
        c = lo > 0 or hi < 0
        sign += s
        ci += c
        both += s and c
    return sign / sims, ci / sims, both / sims


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", action="append", required=True, metavar="MODEL:SUITE:RUNDIR")
    ap.add_argument("--arm", default="A")
    ap.add_argument("--sims", type=int, default=2000)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--other", action="append", default=[], metavar="MODEL:SUITE:RUNDIR",
                    help="an older run of the same arm, for a real cross-session A/A comparison")
    a = ap.parse_args(argv)
    data = verdict.load(a.inputs)
    older = verdict.load(a.other) if a.other else {}
    for model, arms in data.items():
        runs = arms[a.arm]
        s, c, b = rates(runs, a.sims, a.alpha)
        print(f"## {model} arm {a.arm}: {len(runs)} runs; nominal alpha {a.alpha}")
        print(f"false pass rate over {a.sims} random A/A splits: sign test {s:.3f}, CI excludes 0 {c:.3f}, both {b:.3f}")
        if model in older and a.arm in older[model]:
            both = {"new": runs, "old": older[model][a.arm]}
            merged = {"new": both["new"], "old": both["old"]}
            d, lo, hi, p, n = verdict.diff(merged, "new", "old")
            print(f"real cross-session A/A (new minus old): {d:+.3f} [{lo:+.3f}, {hi:+.3f}] sign p {p:.2f} over {n} repos")


if __name__ == "__main__":
    main()
