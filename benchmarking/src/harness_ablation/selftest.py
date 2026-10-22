"""Validate the framework on your own machine, model and suite before you trust a verdict from it.

Runs the baseline (A), the oracle (O, positive control), the handicap (H, negative control) and the raw model
through the adapter contract (RAWX), then checks that the framework behaves:
  1. oracle: recall above baseline, CI over repos above 0            (it can see a real gain)
  2. adapter: raw model through --arm-cmd ties the baseline, CI holds 0 (adapters are faithful)
  3. handicap: truncation up by more than 10 points, or recall CI below 0 (it can see harm)
  4. A/A: false-pass rate over 1,000 random splits of the baseline at or below 10%   (it does not invent winners)
Prints PASS or FAIL per check plus the minimum detectable gain; exits 1 if any check fails. The default suite is
every repo in the suite (51 for cve after `ablate build-cve`; fewer repos can leave the suite too small to
see even the oracle, which the command then says). On Haiku at 2 reps it costs on the order of $10.

Usage: uv run ablate selftest [--model haiku] [--suite cve] [--reps 2] [--workers 5] [--run-root DIR] [--repos a,b,c]
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import calibrate, power, run_eval, suites, verdict

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "examples" / "adapters" / "raw_claude.sh"


def evaluate(data):
    """data: {arm: {(repo, rep): per-run dict}} (verdict.load shape, one model) -> list of (name, passed, detail)."""
    out = []
    d, lo, hi, p, n = verdict.diff(data, "O", "A")
    out.append(("oracle gain visible", lo > 0, f"O minus A {d:+.3f} [{lo:+.3f}, {hi:+.3f}] over {n} repos"))
    d, lo, hi, p, n = verdict.diff(data, "RAWX", "A")
    out.append(("adapter ties baseline", lo <= 0 <= hi, f"RAWX minus A {d:+.3f} [{lo:+.3f}, {hi:+.3f}]"))
    d, lo, hi, p, n = verdict.diff(data, "H", "A")
    trunc = lambda arm: 1 - sum(v["ok"] for v in data[arm].values()) / len(data[arm])
    out.append(("handicap harm visible", trunc("H") - trunc("A") > 0.10 or hi < 0,
                f"H minus A {d:+.3f} [{lo:+.3f}, {hi:+.3f}]; truncation {trunc('H'):.2f} vs {trunc('A'):.2f}"))
    _, ci, both = calibrate.rates(data["A"], 1000, 0.05)[0:3]
    out.append(("A/A false pass rate <= 10%", both <= 0.10, f"{both:.3f} (CI-only {ci:.3f})"))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="haiku")
    ap.add_argument("--suite", default="cve", choices=list(suites.SUITES))
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--repos", help="comma list; default: every repo in the suite")
    ap.add_argument("--run-root", default=str(suites.RUNS / "selftest"))
    a = ap.parse_args(argv)
    repos = a.repos
    root = Path(a.run_root)
    common = ["--suite", a.suite, "--reps", str(a.reps), "--model", a.model, "--workers", str(a.workers)]
    if repos:
        common += ["--repos", repos]
    steps = {"A": ["--arms", "A"], "O": ["--arms", "O"], "H": ["--arms", "H"],
             "RAWX": ["--arm-cmd", f"RAWX=bash {ADAPTER}"]}
    dirs = {name: root / f"{a.suite}-{a.model}-{name}" for name in steps}

    def go(name):
        print(f"== {name} started", flush=True)
        run_eval.main(common + steps[name] + ["--run-dir", str(dirs[name])])
        print(f"== {name} done", flush=True)

    with ThreadPoolExecutor(len(steps)) as ex:  # the four arms are independent; run them side by side
        list(ex.map(go, steps))
    dirs = [f"{a.model}:{a.suite}:{d}" for d in dirs.values()]
    spent = sum(r["gen_cost"] + r.get("verify_cost", 0) for d in dirs
                for r in (json.loads(f.read_text()) for f in Path(d.split(":", 2)[2]).glob("*.json")))
    print(f"\nspent ${spent:.2f} (list-price equivalent) across these run directories")
    data = verdict.load(dirs)[a.model]
    checks = evaluate(data)
    print("\nSELF-TEST RESULT")
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}: {detail}")
    pilot = power.base_rates(data["A"])
    vals = list(pilot.values())
    ds = [0.05, 0.10, 0.15, 0.20, 0.30]
    pw = [(d, power.simulate(vals, len(vals), a.reps, d, 0.05, 200)) for d in ds]
    mde = next((d for d, x in pw if x >= 0.8), None)
    print(f"  power at {len(vals)} repos: " + ", ".join(f"{d:.2f}:{x:.2f}" for d, x in pw)
          + f"; smallest detectable gain at 80%: {mde if mde else 'above ' + str(ds[-1])}")
    if not checks[0][1] and not (mde and mde <= 0.2):
        print("The oracle check failed while the power line shows this suite cannot detect gains this small: the suite is "
              "underpowered for this model. Add repos (see `ablate power`) before trusting any verdict from it.")
    if not all(ok for _, ok, _ in checks):
        print("A failed check means a verdict from this suite and model is not trustworthy yet (see docs/FRAMEWORK.md).")
        sys.exit(1)


if __name__ == "__main__":
    main()
