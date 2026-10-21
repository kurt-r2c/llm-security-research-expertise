import json
from pathlib import Path

import pytest

from harness_ablation import harness, pairwise, score, suites


@pytest.mark.parametrize("suite", ["ssrf", "wide", "mixup", "cve"])
def test_gold_loads_and_labels_resolve(suite):
    # Scorer refuses to build if a label matches nothing or a TP window touches a decoy window.
    sc = score.Scorer(suite)
    assert sc.gold


@pytest.mark.parametrize("suite", ["ssrf", "wide", "mixup"])
def test_every_corpus_repo_has_gold_and_vice_versa(suite):
    cfg = suites.SUITES[suite]
    repos = {p.name for p in cfg["corpus"].iterdir() if p.is_dir()}
    assert repos == set(json.loads(cfg["gold"].read_text()))


def test_staged_copy_hides_gold(tmp_path):
    cfg = suites.SUITES["wide"]
    repo = sorted(p for p in cfg["corpus"].iterdir() if p.is_dir())[0]
    cwd = harness.stage(repo)
    assert not list(cwd.parent.rglob("gold*"))


def test_classify_cve_window():
    sc = score.Scorer("cve")
    repo, g = next(iter(sc.gold.items()))
    h = g["tp"][0]
    hit = {"file": h["file"], "line": h["to"] + sc.tol, "trace": []}
    miss = {"file": h["file"], "line": h["to"] + sc.tol + 1, "trace": []}
    assert sc.classify(repo, hit)[0] == "tp"
    assert sc.classify(repo, miss)[0] == "other"


def test_classify_cve_uses_trace_tail():
    sc = score.Scorer("cve")
    repo, g = next(iter(sc.gold.items()))
    h = g["tp"][0]
    f = {"file": "elsewhere.js", "line": 1, "trace": [{"file": h["file"], "line": h["from"]}]}
    assert sc.classify(repo, f)[0] == "tp"


def test_sign_p_exact():
    assert pairwise.sign_p([1, 1, 1, 1, 1]) == pytest.approx(2 / 32)
    assert pairwise.sign_p([0, 0]) == 1.0
    assert pairwise.sign_p([1, -1]) == 1.0


def test_boot_is_deterministic_and_brackets_mean():
    d = [0.1, 0.0, 0.2, -0.1, 0.1, 0.0]
    lo, hi = pairwise.boot(d)
    assert (lo, hi) == pairwise.boot(d)
    assert lo <= sum(d) / len(d) <= hi


def test_by_repo_averages_reps_within_repo():
    keys = [("a", 1), ("a", 2), ("b", 1)]
    assert pairwise.by_repo(keys, [1.0, 0.0, 1.0]) == [0.5, 1.0]


def _record(sc, repo, verdict):
    g = sc.gold[repo]["tp"][0]
    line = sc.sink_lines(repo, g)[0]
    f = {"file": g["file"], "line": line, "trace": []}
    return {"repo": repo, "findings": [{"finding": f, "verdict": {"verdict": verdict}}],
            "gen_cost": 1.0, "verify_cost": 0.5}


def test_run_metrics_gate_filters_unconfirmed():
    sc = score.Scorer("wide")
    repo = next(r for r, g in sc.gold.items() if g["tp"])
    assert pairwise.run_metrics(sc, _record(sc, repo, "REFUTED"), "") == (1, 0, 1.0)
    assert pairwise.run_metrics(sc, _record(sc, repo, "REFUTED"), "G") == (0, 0, 1.5)
    assert pairwise.run_metrics(sc, _record(sc, repo, "CONFIRMED"), "G") == (1, 0, 1.5)


def test_config_id_changes_with_each_input(monkeypatch, tmp_path):
    base = suites.config_id("wide", "sonnet", None)
    assert base == suites.config_id("wide", "sonnet", None)
    assert base != suites.config_id("wide", "haiku", None)
    assert base != suites.config_id("ssrf", "sonnet", None)
    skills = tmp_path / "skills"
    skills.mkdir()
    (skills / "a.md").write_text("x")
    with_skills = suites.config_id("wide", "sonnet", skills)
    assert with_skills != base
    (skills / "a.md").write_text("y")
    assert suites.config_id("wide", "sonnet", skills) != with_skills
    guides = tmp_path / "guides"
    guides.mkdir()
    (guides / "INDEX.md").write_text("g")
    assert suites.config_id("wide", "sonnet", None, guides) != base
    monkeypatch.setitem(suites.FACTS, "wide", "different note")
    assert suites.config_id("wide", "sonnet", None) != base


def test_config_id_hashes_cve_facts(monkeypatch):
    base = suites.config_id("cve", "sonnet", None)
    monkeypatch.setattr(suites, "CVE_NOTE", suites.CVE_NOTE + " extra")
    assert suites.config_id("cve", "sonnet", None) != base


def test_every_cve_repo_has_a_description():
    for repo in json.loads(suites.SUITES["cve"]["gold"].read_text()):
        assert suites.facts_for("cve", repo)
