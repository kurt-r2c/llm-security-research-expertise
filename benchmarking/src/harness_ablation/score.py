"""Score runs against a gold file. Gold lines are resolved by regex, never by agent output.

Usage: uv run ablate score [--suite ssrf|wide|mixup|cve] [--run-dir DIR]
"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from . import suites


class Scorer:
    def __init__(self, suite, strict=False):
        cfg = suites.SUITES[suite]
        self.corpus, self.tol, self.strict = cfg["corpus"], cfg["tol"], strict
        self.gold = json.loads(cfg["gold"].read_text())
        self.check_overlap()

    def sink_lines(self, repo, item):
        lines = (self.corpus / repo / item["file"]).read_text().splitlines()
        start, end = 0, len(lines)
        if item.get("after"):
            start = next(i for i, ln in enumerate(lines) if re.search(item["after"], ln))
        if item.get("until"):
            end = next(i for i, ln in enumerate(lines) if i > start and re.search(item["until"], ln))
        return [i + 1 for i, ln in enumerate(lines) if start <= i < end and re.search(item["sink"], ln)]

    def item_tol(self, item):
        return item.get("tol", self.tol)

    def check_overlap(self):
        """Every label must resolve, and no TP window may touch a decoy window."""
        for repo, g in self.gold.items():
            if "advisory" in g:
                continue
            res = {k: [(i, Path(x["file"]).name, self.sink_lines(repo, x)) for i, x in enumerate(g[k])]
                   for k in ("tp", "decoy")}
            for kind, entries in res.items():
                for i, _, lines in entries:
                    if not lines:
                        raise SystemExit(f"{repo} {kind}[{i}]: pattern matches nothing")
            for ti, tf, tl in res["tp"]:
                for di, df, dl in res["decoy"]:
                    w = self.item_tol(g["tp"][ti]) + self.item_tol(g["decoy"][di])
                    if tf == df and any(abs(a - b) <= w for a in tl for b in dl):
                        raise SystemExit(f"{repo}: TP and decoy windows touch ({tl} vs {dl}, width {w})")

    def n_gold(self, repo):
        g = self.gold[repo]
        return 1 if "advisory" in g else len(g["tp"])

    def classify_cve(self, repo, f):
        """Real advisory: TP if the finding (or its trace tail) lands within tol lines of a fix hunk."""
        def same(a, b):
            a, b = a.lstrip("./"), b.lstrip("./")
            return a.endswith(b) or b.endswith(a)
        cand = [(f["file"], f["line"])] + [(t["file"], t["line"]) for t in f["trace"][-2:]]
        for h in self.gold[repo]["tp"]:
            if any(same(cf, h["file"]) and h["from"] - self.tol <= cl <= h["to"] + self.tol for cf, cl in cand):
                return "tp", 0
        return "other", None

    def classify(self, repo, f):
        """Match on the finding's own line first, then on the tail of its trace."""
        if "advisory" in self.gold[repo]:
            return self.classify_cve(repo, f)
        primary = [(f["file"], f["line"])]
        tail = [(t["file"], t["line"]) for t in f["trace"][-2:]]
        for cand in (primary, primary + tail):
            for kind in ("tp", "decoy"):
                for i, item in enumerate(self.gold[repo][kind]):
                    want = self.sink_lines(repo, item)
                    if any(Path(cf).name == Path(item["file"]).name
                           and any(abs(cl - w) <= self.item_tol(item) for w in want) for cf, cl in cand):
                        if item.get("neutral") and not self.strict:
                            return "neutral", i
                        return kind, i
        return "other", None

    def score(self, run_dir, gate, by_class=False):
        agg = defaultdict(lambda: defaultdict(float))
        for p in sorted(Path(run_dir).glob("*.json")):
            r = json.loads(p.read_text())
            arm, repo = r["arm"], r["repo"]
            cls = self.gold[repo].get("cls", "all") if by_class else "all"
            a = agg[(arm + ("+gate" if gate else ""), cls)]
            a["runs"] += 1
            a["cost"] += r["gen_cost"] + (r["verify_cost"] if gate else 0)
            hit, shown = set(), 0
            for e in r["findings"]:
                if gate and (e["verdict"] or {}).get("verdict") != "CONFIRMED":
                    continue
                kind, i = self.classify(repo, e["finding"])
                shown += kind != "neutral"
                if kind == "tp":
                    a["tp"] += 1
                    hit.add(i)
                elif kind == "neutral":
                    a["neutral"] += 1
                else:
                    a["fp_" + kind] += 1
            a["gold"] += self.n_gold(repo)
            a["found"] += len(hit)
            a["clean_runs"] += not self.n_gold(repo)
            a["clean_fp_runs"] += (not self.n_gold(repo)) and shown > 0
        return agg


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="ssrf")
    ap.add_argument("--run-dir")
    ap.add_argument("--by-class", action="store_true")
    ap.add_argument("--strict", action="store_true", help="count adjudicated-real/ambiguous as FP (original scoring)")
    a = ap.parse_args(argv)
    run_dir = Path(a.run_dir) if a.run_dir else suites.latest_run_dir(a.suite)
    if run_dir is None:
        raise SystemExit("no runs")
    print("run dir:", run_dir)
    sc = Scorer(a.suite, a.strict)
    rows = {}
    for gate in (False, True):
        rows.update(sc.score(run_dir, gate, a.by_class))
    print(f"{'arm':8} {'class':12} {'runs':>4} {'TP':>4} {'FP-decoy':>8} {'FP-other':>8} {'neutral':>7} {'prec':>6} {'recall':>6} {'$/run':>7} {'clean-FP':>9}")
    for (arm, cls) in sorted(rows, key=lambda k: (k[1], k[0])):
        x = rows[(arm, cls)]
        fp = x["fp_decoy"] + x["fp_other"]
        prec = x["tp"] / (x["tp"] + fp) if x["tp"] + fp else float("nan")
        rec = x["found"] / x["gold"] if x["gold"] else float("nan")
        print(f"{arm:8} {cls:12} {int(x['runs']):4} {int(x['tp']):4} {int(x['fp_decoy']):8} {int(x['fp_other']):8} {int(x['neutral']):7} "
              f"{prec:6.2f} {rec:6.2f} {x['cost']/x['runs']:7.3f} {int(x['clean_fp_runs'])}/{int(x['clean_runs'])}")

