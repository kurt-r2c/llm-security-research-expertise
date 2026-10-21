"""Mechanical advisory screener: find post-cutoff GitHub advisories with a single small fix commit.

Public GitHub data only, via the authenticated `gh api` CLI. No model results are used anywhere;
selection is deterministic. Output: a candidate list for extending build_cve_corpus.SPECS.
Usage: python -m harness_ablation.screen --since 2026-07-01 --want 30 --out data/cve-candidates.json
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ECOSYSTEMS = ["pip", "npm", "go", "maven", "composer", "rubygems", "nuget", "rust"]
LANG_EXT = {
    ".py": "python", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
    ".go": "go", ".java": "java", ".php": "php", ".rb": "ruby", ".cs": "csharp", ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c",
}
# same exclusion idea as build_cve_corpus.SKIP, applied to full repo paths
SKIP = re.compile(r"(^|/)(tests?|spec|__tests__|testdata|docs?|examples?|\.github)(/|$)|\.md$")
TEST_FILE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*Tests?\.\w+|[^/]*\.(test|spec)\.\w+|conftest\.py)$")
MAX_FILES, MAX_LINES, MAX_REPO_KB = 2, 70, 40 * 1024
COMMIT_URL = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-f]{7,40})(?:[/?#].*)?$", re.I)
# first match wins, so order is priority
BUCKETS = [
    ("ssrf", r"ssrf|server[- ]side request"),
    ("deserialization", r"deserializ|unpickl|pickle|unserialize|yaml\.load|object injection"),
    ("injection", r"inject|xss|cross[- ]site scripting|remote code|code execution|rce\b|\bsqli?\b|template|command execution|sanitiz"),
    ("path", r"path|traversal|zip slip|symlink|arbitrary file|directory"),
    ("auth", r"auth|bypass|permission|privilege|access control|idor|impersonat|unauthori"),
    ("crypto", r"crypto|token|jwt|signature|certificate|\bkey\b|hmac|password|secret|\btls\b|nonce"),
    ("dos", r"denial|\bdos\b|redos|regular expression|regex|infinite|exhaust|crash|unbounded|resource"),
]


class RateLimited(SystemExit):
    pass


def gh(path, *fields, sleep=0.3, include=False):
    """Call `gh api`; stop with a clear message on a rate-limit 403/429."""
    args = ["gh", "api", "-X", "GET"] + (["-i"] if include else []) + [path]
    for f in fields:
        args += ["-f", f]
    time.sleep(sleep)
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        err = (p.stderr + p.stdout).lower()
        if "rate limit" in err or "http 403" in err or "http 429" in err:
            raise RateLimited("GitHub API rate limit hit (403/429); stopping. Wait for reset (`gh api rate_limit`) and rerun.")
        raise RuntimeError(f"gh api {path} failed: {p.stderr.strip()[:200]}")
    return p.stdout


def list_advisories(eco, since, sleep=0.3):
    """Reviewed advisories for one ecosystem published >= since, following Link rel=next cursors."""
    out, after = [], None
    while True:
        fields = ["type=reviewed", f"ecosystem={eco}", f"published=>={since}", "per_page=100"]
        if after:
            fields.append(f"after={after}")
        raw = gh("/advisories", *fields, sleep=sleep, include=True)
        head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
        out += [a for a in json.loads(body) if a["published_at"][:10] >= since]
        m = re.search(r'<[^>]*[?&]after=([^&>]+)[^>]*>;\s*rel="next"', head)
        if not m:
            return out
        after = m.group(1).replace("%3D", "=")


def fix_commit(adv):
    """(repo, sha) if the advisory references exactly one distinct commit, else None."""
    seen = {}
    for url in adv.get("references") or []:
        m = COMMIT_URL.match(url or "")
        if m:
            key = (f"{m.group(1)}/{m.group(2)}".lower(), m.group(3).lower()[:7])
            if key not in seen or len(m.group(3)) > len(seen[key][1]):
                seen[key] = (f"{m.group(1)}/{m.group(2)}", m.group(3).lower())
    return next(iter(seen.values())) if len(seen) == 1 else None


def cls_keyword(summary):
    s = (summary or "").lower()
    for name, rx in BUCKETS:
        if re.search(rx, s):
            return name
    return "other"


def is_source(path):
    ext = Path(path).suffix.lower()
    return not SKIP.search(path) and not TEST_FILE.search(path) and ext in LANG_EXT and not path.endswith(".d.ts")


def check_commit(meta, since, max_files=MAX_FILES, max_lines=MAX_LINES):
    """Apply commit-level filters. Returns (files, lines_changed) or None if rejected."""
    if len(meta.get("parents") or []) != 1:
        return None
    date = ((meta.get("commit") or {}).get("committer") or {}).get("date", "")
    if date[:10] < since:
        return None
    src = [f for f in meta.get("files") or [] if is_source(f["filename"])]
    if not 1 <= len(src) <= max_files:
        return None
    lines = sum(f.get("additions", 0) + f.get("deletions", 0) for f in src)
    if lines > max_lines or len(meta.get("files") or []) >= 300:
        return None
    return sorted(f["filename"] for f in src), lines


def common_sub(files):
    tops = {f.split("/")[0] if "/" in f else "." for f in files}
    return tops.pop() if len(tops) == 1 else "."


def short_name(repo, kw, taken):
    base = re.sub(r"[^a-z0-9]+", "", repo.split("/")[1].lower()) or "repo"
    cid, n = f"{base}-{kw}", 2
    while cid in taken:
        cid, n = f"{base}-{kw}{n}", n + 1
    return cid


def order_advisories(advs):
    """Deterministic order: round-robin over ecosystems; within one, newest first then GHSA id."""
    by = {}
    for a in advs:
        by.setdefault(a["eco"], []).append(a)
    for lst in by.values():
        lst.sort(key=lambda a: (-int(re.sub(r"\D", "", a["published_at"])), a["ghsa_id"]))
    order = [e for e in ECOSYSTEMS if e in by] + sorted(e for e in by if e not in ECOSYSTEMS)
    out = []
    for i in range(max((len(v) for v in by.values()), default=0)):
        out += [by[e][i] for e in order if i < len(by[e])]
    return out


def select(ordered, evaluate, want, per_repo=3, per_bucket=2):
    """Walk the ordered advisories lazily; accept when caps allow and evaluate() returns a candidate."""
    picked, repos, buckets = [], {}, {}
    for adv in ordered:
        if len(picked) >= want:
            break
        kw = cls_keyword(adv.get("summary"))
        repo = (fix_commit(adv) or ("", ""))[0].lower()
        if not repo or repos.get(repo, 0) >= per_repo or buckets.get(kw, 0) >= per_bucket:
            continue
        cand = evaluate(adv)
        if cand is None:
            continue
        picked.append(cand)
        repos[repo] = repos.get(repo, 0) + 1
        buckets[kw] = buckets.get(kw, 0) + 1
    return picked


def main(argv=None):
    ap = argparse.ArgumentParser(prog="harness_ablation.screen")
    ap.add_argument("--since", default="2026-07-01")
    ap.add_argument("--want", type=int, default=30)
    ap.add_argument("--out", default="data/cve-candidates.json")
    ap.add_argument("--per-bucket", type=int, default=2)
    ap.add_argument("--per-repo", type=int, default=3)
    ap.add_argument("--sleep", type=float, default=0.3)
    a = ap.parse_args(argv)

    from .build_cve_corpus import SPECS
    have = {(s[1].lower(), s[2][:7]) for s in SPECS}
    advs = []
    for eco in ECOSYSTEMS:
        got = list_advisories(eco, a.since, a.sleep)
        print(f"{eco}: {len(got)} reviewed advisories since {a.since}", file=sys.stderr)
        advs += [dict(x, eco=eco) for x in got]
    seen, uniq = set(), []
    for x in advs:  # an advisory can list several ecosystems; keep the first (fixed ecosystem order)
        if x["ghsa_id"] not in seen:
            seen.add(x["ghsa_id"])
            uniq.append(x)
    with_commit = [x for x in uniq if fix_commit(x)]
    print(f"{len(uniq)} unique advisories, {len(with_commit)} with exactly one fix commit URL", file=sys.stderr)

    repo_kb, taken, why = {}, {s[0] for s in SPECS}, {}

    def evaluate(adv):
        repo, sha = fix_commit(adv)
        if (repo.lower(), sha[:7]) in have:
            why["already in SPECS"] = why.get("already in SPECS", 0) + 1
            return None
        try:
            if repo not in repo_kb:
                repo_kb[repo] = json.loads(gh(f"repos/{repo}", sleep=a.sleep)).get("size", 0)
            if repo_kb[repo] >= MAX_REPO_KB:
                why["repo >= 40MB"] = why.get("repo >= 40MB", 0) + 1
                return None
            meta = json.loads(gh(f"repos/{repo}/commits/{sha}", sleep=a.sleep))
        except RuntimeError as e:
            why["fetch failed"] = why.get("fetch failed", 0) + 1
            print("skip", adv["ghsa_id"], e, file=sys.stderr)
            return None
        res = check_commit(meta, a.since)
        if res is None:
            why["commit filters"] = why.get("commit filters", 0) + 1
            return None
        files, lines = res
        kw = cls_keyword(adv.get("summary"))
        cid = short_name(repo, kw, taken)
        taken.add(cid)
        return {"id": cid, "repo": repo, "sha": meta["sha"], "ghsa": adv["ghsa_id"], "sub": common_sub(files),
                "files": files, "lines_changed": lines, "ecosystem": adv["eco"], "cls_keyword": kw}

    picked = select(order_advisories(with_commit), evaluate, a.want, a.per_repo, a.per_bucket)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(picked, indent=1) + "\n")
    print(f"{'id':32} {'eco':9} {'class':16} {'lines':>5}  ghsa / repo@sha / files")
    for c in picked:
        print(f"{c['id']:32} {c['ecosystem']:9} {c['cls_keyword']:16} {c['lines_changed']:>5}  "
              f"{c['ghsa']} {c['repo']}@{c['sha'][:10]} {','.join(c['files'])}")
    print(f"\n{len(picked)} candidates (wanted {a.want}); rejects among evaluated: {why}", file=sys.stderr)
    if len(picked) < a.want:
        print("fewer than wanted: pool exhausted or per-repo/per-bucket caps reached", file=sys.stderr)


if __name__ == "__main__":
    main()
