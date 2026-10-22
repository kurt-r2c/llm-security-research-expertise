"""Patch-differential precision proxy for the real-CVE suite.

The CVE suite has no complete gold, so precision cannot be scored. But the fix commit tells us one thing
for certain: the lines it rewrote are no longer vulnerable. Run an arm on the PRE-fix tree (suite cve) and
on the FIX tree (suite cvefix, `ablate build-cve --fixed`). A finding within the window of the fixed site on
the fix tree is a false alarm. Per repo, with p = rate of pre-fix hits and q = rate of fix-tree alarms:
  discrimination = p - q   (1: finds the bug and stays quiet once fixed; 0: cannot tell fixed from vulnerable)
Candidate arms are compared with the baseline on p, q and p - q (repo is the unit).

Usage: uv run ablate fixcheck --pre sonnet:cve:runs/cve-sonnet-base --pre sonnet:cve:runs/cve-sonnet-K1 \\
                              --post sonnet:cvefix:runs/cvefix-sonnet-base --post sonnet:cvefix:runs/cvefix-sonnet-K1 [--base A]
"""
import argparse

from . import pairwise, verdict


def per_repo(runs):
    acc = {}
    for (repo, _), v in runs.items():
        acc.setdefault(repo, []).append(min(v["found"], v["gold"]) / v["gold"] if v["gold"] else 0.0)
    return {r: sum(x) / len(x) for r, x in acc.items()}


def summarize(pre, post):
    """-> {arm: {repo: (p, q)}} over repos present on both sides."""
    out = {}
    # gated (+G) arms need verdicts on both sides; fix-tree runs are usually made with --no-verify, so raw only
    for arm in {x for x in set(pre) & set(post) if not x.endswith("+G")}:
        p, q = per_repo(pre[arm]), per_repo(post[arm])
        out[arm] = {r: (p[r], q[r]) for r in set(p) & set(q)}
    return out


def compare(arms, base, arm):
    repos = sorted(set(arms[base]) & set(arms[arm]))
    res = {}
    for name, f in (("pre-fix hit", lambda v: v[0]), ("fix-tree alarm", lambda v: v[1]), ("discrimination", lambda v: v[0] - v[1])):
        d = [f(arms[arm][r]) - f(arms[base][r]) for r in repos]
        lo, hi = pairwise.boot(d)
        res[name] = (sum(d) / len(d), lo, hi, pairwise.sign_p(d))
    return len(repos), res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pre", action="append", required=True, metavar="MODEL:cve:RUNDIR")
    ap.add_argument("--post", action="append", required=True, metavar="MODEL:cvefix:RUNDIR")
    ap.add_argument("--base", default="A")
    a = ap.parse_args(argv)
    pre, post = verdict.load(a.pre), verdict.load(a.post)
    for model in sorted(set(pre) & set(post)):
        arms = summarize(pre[model], post[model])
        print(f"## {model}")
        print(f"{'arm':8} {'repos':>5} {'pre-fix hit':>12} {'fix-tree alarm':>15} {'discrimination':>15}")
        for arm in sorted(arms):
            v = list(arms[arm].values())
            p, q = sum(x[0] for x in v) / len(v), sum(x[1] for x in v) / len(v)
            print(f"{arm:8} {len(v):5} {p:12.3f} {q:15.3f} {p - q:15.3f}")
        for arm in sorted(arms):
            if arm == a.base or a.base not in arms:
                continue
            n, res = compare(arms, a.base, arm)
            print(f"{arm} minus {a.base} ({n} repos): " + "; ".join(
                f"{k} {d:+.3f} [{lo:+.3f},{hi:+.3f}] p {p:.2f}" for k, (d, lo, hi, p) in res.items()))


if __name__ == "__main__":
    main()
