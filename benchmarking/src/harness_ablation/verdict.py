"""Apply a written decision rule to run directories and print KEEP / DISCARD per candidate arm.

The rule is a small JSON file, committed before the runs (see docs/FRAMEWORK.md, "Rule file reference", and
rule.example.json; keys starting with "_" are ignored, "placebo": null runs without a placebo):
  {"baseline": "A", "placebo": "P", "candidates": ["K1", "K2"], "mode": "", "alpha": 0.05,
   "harm_floor": -0.05, "precision_floor": -0.05,
   "delivery": {"K2": {"min_read_fraction": 0.5, "read_marker": "/expertise/"}}, "truncation_flag": 0.10}
For each candidate and model: pooled recall difference candidate minus baseline over all suites, repo as
the unit, bootstrap 95% CI and exact sign test; Holm adjustment over all (candidate, model) tests.
KEEP needs, on at least one model: CI above 0 and Holm p below alpha. And on every model: point estimate
not below harm_floor, precision (synthetic suites) not below precision_floor versus baseline. And
candidate above placebo (point estimate) on the models where it passes; delivery check where configured.

Usage: uv run ablate verdict --rule rule.json --in sonnet:cve:runs/cve-sonnet-base --in sonnet:cve:runs/cve-sonnet-K1 ...
"""
import argparse
import json
import sys
from pathlib import Path

from . import pairwise, score


def load(specs):
    """specs: ['MODEL:SUITE:DIR', ...] -> per model: runs[arm][(repo,rep)] = dict of per-run numbers."""
    scorers, out = {}, {}
    for spec in specs:
        model, suite, d = spec.split(":", 2)
        sc = scorers.setdefault(suite, score.Scorer(suite))
        for p in Path(d).glob("*.json"):
            r = json.loads(p.read_text())
            for mode in ("", "G"):
                arm = r["arm"] + ("+G" if mode else "")
                found, fp, _ = pairwise.run_metrics(sc, r, mode)
                gold = sc.n_gold(r["repo"])
                out.setdefault(model, {}).setdefault(arm, {})[(r["repo"], r["rep"])] = {
                    "found": found, "fp": fp, "gold": gold, "synthetic": "advisory" not in sc.gold[r["repo"]],
                    "ok": r["status"] == "success", "reads": r["trace"].get("reads", [])}
    return out


def diff(runs, x, y):
    keys = sorted(set(runs[x]) & set(runs[y]))
    keys = [k for k in keys if runs[x][k]["gold"]]
    per_repo = pairwise.by_repo(keys, [(runs[x][k]["found"] - runs[y][k]["found"]) / runs[x][k]["gold"] for k in keys])
    lo, hi = pairwise.boot(per_repo)
    return sum(per_repo) / len(per_repo), lo, hi, pairwise.sign_p(per_repo), len(per_repo)


def precision(runs, arm):
    rs = [v for v in runs[arm].values() if v["synthetic"]]
    tp, fp = sum(v["found"] for v in rs), sum(v["fp"] for v in rs)
    return tp / (tp + fp) if tp + fp else None


def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    adj, run = [0.0] * len(ps), 0.0
    for rank, i in enumerate(order):
        run = max(run, min(1.0, (len(ps) - rank) * ps[i]))
        adj[i] = run
    return adj


def check_arms(rule, data):
    """Readable errors for a rule that names arms the run directories do not hold, and a warning for ragged coverage."""
    suf = "+G" if rule.get("mode", "") == "G" else ""
    need = [rule["baseline"]] + list(rule["candidates"]) + ([rule["placebo"]] if rule.get("placebo") else [])
    for model, arms in data.items():
        for arm in need:
            if arm + suf not in arms:
                have = sorted(a for a in arms if not a.endswith("+G"))
                hint = ' (set "placebo": null in the rule to run without one)' if arm == rule.get("placebo") else ""
                raise SystemExit(f"rule names arm {arm!r} but no runs for model {model!r} contain it; arms found: {have}{hint}")
        sizes = {a: len({k[0] for k in arms[a + suf]}) for a in need}
        if len(set(sizes.values())) > 1:
            print(f"WARNING {model}: arms cover different numbers of repos {sizes}; comparisons use only the repos both arms have",
                  file=sys.stderr)


def decide(rule, data):
    rule = {k: v for k, v in rule.items() if not k.startswith("_")}  # "_comment" style keys are documentation
    check_arms(rule, data)
    base, plc, mode = rule["baseline"], rule.get("placebo") or None, rule.get("mode", "")
    suf = "+G" if mode == "G" else ""
    tests = [(c, m) for c in rule["candidates"] for m in sorted(data)]
    rows = {}
    for c, m in tests:
        d, lo, hi, p, n = diff(data[m], c + suf, base + suf)
        rows[(c, m)] = {"d": d, "lo": lo, "hi": hi, "p": p, "n": n}
        if plc:
            rows[(c, m)]["vs_placebo"] = diff(data[m], c + suf, plc + suf)[0]
    for (key, r), a in zip(rows.items(), holm([r["p"] for r in rows.values()])):
        r["holm"] = a
    out = {}
    for c in rule["candidates"]:
        why, passes = [], []
        for m in sorted(data):
            r = rows[(c, m)]
            if r["lo"] > 0 and r["holm"] < rule.get("alpha", 0.05):
                passes.append(m)
            if r["hi"] < 0 and r["holm"] < rule.get("alpha", 0.05):
                why.append(f"significantly WORSE than baseline on {m} ({r['d']:+.3f}, Holm {r['holm']:.2f})")
            if r["d"] < rule.get("harm_floor", -0.05):
                why.append(f"harm floor breached on {m} ({r['d']:+.3f})")
            if "precision_floor" in rule:
                pc, pb = precision(data[m], c + suf), precision(data[m], base + suf)
                if pc is not None and pb is not None and pc - pb < rule["precision_floor"]:
                    why.append(f"precision down {pc - pb:+.3f} on {m}")
            if "truncation_flag" in rule:
                tc = 1 - sum(v["ok"] for v in data[m][c].values()) / len(data[m][c])
                tb = 1 - sum(v["ok"] for v in data[m][base].values()) / len(data[m][base])
                if tc - tb > rule["truncation_flag"]:
                    why.append(f"truncation rate {tc:.2f} vs {tb:.2f} on {m}")
            dl = rule.get("delivery", {}).get(c)
            if dl:
                frac = sum(any(dl["read_marker"] in x for x in v["reads"]) for v in data[m][c].values()) / len(data[m][c])
                if frac < dl["min_read_fraction"]:
                    why.append(f"delivery failure on {m}: guides read in {frac:.0%} of runs")
        if not passes:
            why.append("primary test not passed on any model")
        elif plc:
            for m in passes:
                if rows[(c, m)]["vs_placebo"] <= 0:
                    why.append(f"not above placebo on {m}")
        out[c] = ("DISCARD", why) if why else ("KEEP", [f"passes on {', '.join(passes)}"])
    return rows, out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule", required=True)
    ap.add_argument("--in", dest="inputs", action="append", required=True, metavar="MODEL:SUITE:RUNDIR")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rule = json.loads(Path(a.rule).read_text())
    rows, out = decide(rule, load(a.inputs))
    if a.json:
        print(json.dumps({"rows": {f"{c}|{m}": r for (c, m), r in rows.items()}, "verdict": out}, indent=1))
        return
    print(f"{'candidate':10} {'model':8} {'repos':>5} {'K-base [95% CI over repos]':>30} {'p':>5} {'holm':>5} {'K-placebo':>10}")
    for (c, m), r in rows.items():
        vp = f"{r['vs_placebo']:+10.3f}" if "vs_placebo" in r else f"{'n/a':>10}"
        print(f"{c:10} {m:8} {r['n']:5} {r['d']:+9.3f} [{r['lo']:+.3f}, {r['hi']:+.3f}] {r['p']:5.2f} {r['holm']:5.2f} {vp}")
    print()
    for c, (v, why) in out.items():
        print(f"{c}: {v} - " + "; ".join(why))
