from harness_ablation import screen as S


def meta(parents=1, date="2026-08-01T00:00:00Z", files=None):
    return {"parents": [{}] * parents, "commit": {"committer": {"date": date}}, "files": files or []}


def f(name, a=5, d=5):
    return {"filename": name, "additions": a, "deletions": d}


def test_fix_commit_single_and_dedupe():
    u = "https://github.com/o/r/commit/" + "a" * 40
    adv = {"references": [u, u, "https://github.com/o/r/commit/" + "a" * 7, "https://x/y"]}
    assert S.fix_commit(adv) == ("o/r", "a" * 40)


def test_fix_commit_zero_or_many():
    assert S.fix_commit({"references": ["https://github.com/o/r/pull/3"]}) is None
    two = ["https://github.com/o/r/commit/" + "a" * 40, "https://github.com/o/r/commit/" + "b" * 40]
    assert S.fix_commit({"references": two}) is None


def test_cls_keyword():
    assert S.cls_keyword("SSRF in fetcher") == "ssrf"
    assert S.cls_keyword("Path traversal in bookmark restore") == "path"
    assert S.cls_keyword("JWT signature not verified") == "crypto"
    assert S.cls_keyword("ReDoS in parser") == "dos"
    assert S.cls_keyword("Something odd") == "other"


def test_is_source():
    assert S.is_source("src/a.py") and S.is_source("lib/x.ts")
    assert not S.is_source("tests/a.py") and not S.is_source("src/__tests__/a.js")
    assert not S.is_source("docs/a.py") and not S.is_source("README.md")
    for n in ["a/foo_test.go", "src/FooTest.php", "src/test_x.py", "a/b.spec.ts", "a/b.test.js", "conftest.py"]:
        assert not S.is_source(n), n
    assert S.is_source("src/latest.py")
    assert not S.is_source(".github/x.py") and not S.is_source("a.json") and not S.is_source("a.d.ts")


def test_check_commit_ok_and_sub():
    r = S.check_commit(meta(files=[f("src/a.py"), f("tests/t.py"), f("CHANGELOG.md")]), "2026-07-01")
    assert r == (["src/a.py"], 10)
    assert S.common_sub(["src/a.py", "src/b/c.py"]) == "src"
    assert S.common_sub(["a.js"]) == "." and S.common_sub(["a/x.go", "b/y.go"]) == "."


def test_check_commit_rejects():
    ok = [f("src/a.py")]
    assert S.check_commit(meta(parents=2, files=ok), "2026-07-01") is None
    assert S.check_commit(meta(date="2026-06-30T00:00:00Z", files=ok), "2026-07-01") is None
    assert S.check_commit(meta(files=[f("a.py"), f("b.py"), f("c.py")]), "2026-07-01") is None
    assert S.check_commit(meta(files=[f("a.py", 40, 31)]), "2026-07-01") is None
    assert S.check_commit(meta(files=[f("a.py", 35, 35)]), "2026-07-01") == (["a.py"], 70)
    assert S.check_commit(meta(files=[f("tests/a.py")]), "2026-07-01") is None


def adv(i, eco, day, summary="x", repo="o/r"):
    return {"ghsa_id": f"GHSA-{i}", "eco": eco, "published_at": f"2026-08-{day:02d}T00:00:00Z", "summary": summary,
            "references": [f"https://github.com/{repo}/commit/" + "a" * 39 + str(i)[-1]]}


def test_order_round_robin():
    advs = [adv(1, "npm", 5), adv(2, "npm", 9), adv(3, "pip", 1), adv(4, "pip", 2), adv(5, "go", 3)]
    ids = [a["ghsa_id"] for a in S.order_advisories(advs)]
    assert ids[:3] == ["GHSA-4", "GHSA-2", "GHSA-5"]  # pip, npm, go with newest first
    assert ids == [a["ghsa_id"] for a in S.order_advisories(list(reversed(advs)))]


def test_select_caps():
    advs = [adv(i, "pip", i, "path traversal", repo=f"o/r{i % 2}") for i in range(1, 9)]
    got = S.select(advs, lambda a: {"ghsa": a["ghsa_id"]}, want=10, per_repo=3, per_bucket=2)
    assert len(got) == 2  # bucket cap
    advs = [adv(i, "pip", i, ["ssrf", "auth", "dos", "crypto"][i % 4], repo="o/same") for i in range(1, 9)]
    got = S.select(advs, lambda a: {"ghsa": a["ghsa_id"]}, want=10)
    assert len(got) == 3  # repo cap
    got = S.select(advs, lambda a: None, want=10)
    assert got == []
    assert len(S.select(advs, lambda a: {"g": 1}, want=1)) == 1
