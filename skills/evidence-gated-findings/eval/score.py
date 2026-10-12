"""Score runs against gold.json. Gold lines are resolved by regex, never by agent output."""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

EVAL = Path(__file__).parent
CORPUS = EVAL / "corpus"
GOLD = json.loads((EVAL / "gold.json").read_text())
TOL = 3


def sink_lines(repo, item):
    text = (CORPUS / repo / item["file"]).read_text().splitlines()
    return [i + 1 for i, ln in enumerate(text) if re.search(item["sink"], ln)]


def classify(repo, f):
    """Return ('tp', idx) | ('decoy', idx) | ('other', None) for a reported finding."""
    lines = {f["file"]: [f["line"]]}
    cand = [(f["file"], f["line"])] + [(t["file"], t["line"]) for t in f["trace"][-2:]]
    for kind in ("tp", "decoy"):
        for i, item in enumerate(GOLD[repo][kind]):
            want = sink_lines(repo, item)
            if any(Path(cf).name == Path(item["file"]).name and any(abs(cl - w) <= TOL for w in want)
                   for cf, cl in cand):
                return kind, i
    return "other", None


def score(gate):
    agg = defaultdict(lambda: defaultdict(float))
    for p in sorted((EVAL / "runs").glob("*.json")):
        r = json.loads(p.read_text())
        arm, repo = r["arm"], r["repo"]
        key = arm + ("+gate" if gate else "")
        a = agg[key]
        a["runs"] += 1
        a["cost"] += r["gen_cost"] + (r["verify_cost"] if gate else 0)
        hit = set()
        for e in r["findings"]:
            if gate and (e["verdict"] or {}).get("verdict") != "CONFIRMED":
                continue
            kind, i = classify(repo, e["finding"])
            if kind == "tp":
                a["tp"] += 1
                hit.add(i)
            else:
                a["fp_" + kind] += 1
        a["gold"] += len(GOLD[repo]["tp"])
        a["found"] += len(hit)
        a["clean_runs"] += not GOLD[repo]["tp"]
        a["clean_fp_runs"] += (not GOLD[repo]["tp"]) and any(
            not gate or (e["verdict"] or {}).get("verdict") == "CONFIRMED" for e in r["findings"])
    return agg


if __name__ == "__main__":
    rows = {}
    for gate in (False, True):
        rows.update(score(gate))
    print(f"{'arm':8} {'runs':>4} {'TP':>4} {'FP-decoy':>8} {'FP-other':>8} {'prec':>6} {'recall':>6} {'$/run':>7} {'clean-repo FP runs':>18}")
    for k in sorted(rows):
        a = rows[k]
        fp = a["fp_decoy"] + a["fp_other"]
        prec = a["tp"] / (a["tp"] + fp) if a["tp"] + fp else float("nan")
        rec = a["found"] / a["gold"]
        print(f"{k:8} {int(a['runs']):4} {int(a['tp']):4} {int(a['fp_decoy']):8} {int(a['fp_other']):8} "
              f"{prec:6.2f} {rec:6.2f} {a['cost']/a['runs']:7.3f} {int(a['clean_fp_runs'])}/{int(a['clean_runs'])}")
