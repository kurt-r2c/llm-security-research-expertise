"""Pairwise comparison of arms on matched (repo, rep) runs.

Arms: A vanilla, B skills, C guides; suffix +G = candidates filtered by the general verifier,
+F = filtered by the verifier given a facts note. Metrics per run: seeded bugs found (recall),
false positives (synthetic suites only), cost. Statistic: paired difference averaged within each repo
(repos are the unit; reps of one repo are correlated), then a bootstrap 95% CI over repos and an exact
two-sided sign test on the non-tied repos.

Usage: uv run ablate pairwise --in wide:runs/DIR [--in cve:runs/DIR2] [--pairs A:B,A:C,...]
"""
import argparse
import itertools
import json
import math
import random
from pathlib import Path

from . import score


def run_metrics(sc, r, mode):
    """mode: '' (raw), 'G' (verdict), 'F' (verdict_facts)."""
    key = {"": None, "G": "verdict", "F": "verdict_facts"}[mode]
    hit, fp, kept = set(), 0, 0
    for e in r["findings"]:
        if key and (e.get(key) or {}).get("verdict") != "CONFIRMED":
            continue
        kept += 1
        kind, i = sc.classify(r["repo"], e["finding"])
        if kind == "tp":
            hit.add(i)
        elif kind != "neutral":
            fp += 1
    cost = r["gen_cost"] + (r.get("verify_cost", 0) if mode == "G" else r.get("verify_facts_cost", 0) if mode == "F" else 0)
    return len(hit), fp, cost


def by_repo(keys, vals):
    """Average matched-rep differences within each repo; the repo is the unit of analysis."""
    acc = {}
    for k, v in zip(keys, vals):
        acc.setdefault(k[0], []).append(v)
    return [sum(v) / len(v) for v in acc.values()]


def sign_p(diffs):
    nz = [d for d in diffs if d]
    n, k = len(nz), sum(d > 0 for d in nz)
    if not n:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(k, n - k) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def boot(diffs, n=4000, seed=1):
    rnd = random.Random(seed)
    m = [sum(rnd.choices(diffs, k=len(diffs))) / len(diffs) for _ in range(n)]
    m.sort()
    return m[int(.025 * n)], m[int(.975 * n)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inputs", action="append", required=True, metavar="SUITE:RUNDIR",
                    help="repeatable; suites are pooled, repos stay the unit")
    ap.add_argument("--pairs", help="comma list like A:B,B:B+G; default all among arms present")
    ap.add_argument("--label", default="")
    a = ap.parse_args(argv)
    scorers, runs = {}, {}
    for spec in a.inputs:
        suite, d = spec.split(":", 1)
        sc = score.Scorer(suite)
        for p in Path(d).glob("*.json"):
            r = json.loads(p.read_text())
            scorers[r["repo"]] = sc
            for mode in ("", "G", "F"):
                if mode == "F" and "verify_facts_cost" not in r:
                    continue
                runs.setdefault(r["arm"] + ("+" + mode if mode else ""), {})[(r["repo"], r["rep"])] = run_metrics(sc, r, mode)
    arms = sorted(runs)
    pairs = [tuple(x.split(":")) for x in a.pairs.split(",")] if a.pairs else list(itertools.combinations(arms, 2))
    synth = not all("advisory" in sc.gold[r] for r, sc in scorers.items())
    print(f"## {a.label}  repos={len(scorers)}  runs/arm={ {k: len(v) for k, v in runs.items()} }")
    print(f"{'X vs Y':12} {'repos':>5} | {'recall d(X-Y) [95% CI over repos]':>36} {'p':>5} | {'FP d(X-Y)':>26} {'p':>5} | {'cost d':>7}")
    for x, y in pairs:
        keys = sorted(set(runs.get(x, {})) & set(runs.get(y, {})))
        if not keys:
            continue
        gold = {k: scorers[k[0]].n_gold(k[0]) for k in keys}
        gk = [k for k in keys if gold[k]]
        rec = by_repo(gk, [(runs[x][k][0] - runs[y][k][0]) / gold[k] for k in gk])
        fp = by_repo(keys, [runs[x][k][1] - runs[y][k][1] for k in keys])
        cost = sum(runs[x][k][2] - runs[y][k][2] for k in keys) / len(keys)

        def fmt(d):
            lo, hi = boot(d)
            return f"{sum(d)/len(d):+.3f} [{lo:+.3f},{hi:+.3f}]"
        fps = fmt(fp) if synth else "n/a (unlabeled)"
        print(f"{x+' vs '+y:12} {len({k[0] for k in keys}):5} | {fmt(rec):>36} {sign_p(rec):5.2f} | "
              f"{fps:>26} {(sign_p(fp) if synth else float('nan')):5.2f} | {cost:+7.3f}")

