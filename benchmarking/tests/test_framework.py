"""Offline tests for the audit-framework pieces: adapters, controls, verdict, power, calibration, fixcheck."""
import json
import random

import pytest

from harness_ablation import build_cve_corpus, calibrate, fixcheck, harness, power, run_eval, suites, verdict


def mkruns(hits, gold=1, ok=True, reps=2, fp=0, synthetic=False, reads=()):
    """hits: {repo: [found per rep]} -> the per-run dict shape produced by verdict.load."""
    return {(r, i + 1): {"found": f, "fp": fp, "gold": gold, "synthetic": synthetic, "ok": ok, "reads": list(reads)}
            for r, fs in hits.items() for i, f in enumerate(fs)}


def test_holm_is_monotone_and_capped():
    adj = verdict.holm([0.01, 0.04, 0.03])
    assert adj == pytest.approx([0.03, 0.06, 0.06])
    assert verdict.holm([0.9, 0.8]) == [0.9, 0.9] or max(verdict.holm([0.9, 0.8])) <= 1.0


def test_decide_keep_discard_harm_and_placebo():
    repos = [f"r{i}" for i in range(12)]
    base = {r: [0, 0] for r in repos}
    win = {r: [1, 1] for r in repos}            # clear gain on every repo
    lose = {r: [0, 0] for r in repos}
    data = {"m": {"A": mkruns(base), "P": mkruns(base), "K1": mkruns(win), "K2": mkruns(lose),
                  "K3": mkruns({r: [1, 1] if i < 2 else [0, 0] for i, r in enumerate(repos)})}}
    rule = {"baseline": "A", "placebo": "P", "candidates": ["K1", "K2", "K3"]}
    _, out = verdict.decide(rule, data)
    assert out["K1"][0] == "KEEP"
    assert out["K2"][0] == "DISCARD"
    assert out["K3"][0] == "DISCARD"           # 2 of 12 repos improving is not enough


def test_decide_harm_floor_blocks_keep():
    repos = [f"r{i}" for i in range(12)]
    data = {"good": {"A": mkruns({r: [0, 0] for r in repos}), "K": mkruns({r: [1, 1] for r in repos})},
            "bad": {"A": mkruns({r: [1, 1] for r in repos}), "K": mkruns({r: [0, 0] for r in repos})}}
    _, out = verdict.decide({"baseline": "A", "candidates": ["K"]}, data)
    assert out["K"][0] == "DISCARD" and any("harm floor" in w for w in out["K"][1])


def test_decide_delivery_and_truncation_flags():
    repos = [f"r{i}" for i in range(12)]
    data = {"m": {"A": mkruns({r: [0, 0] for r in repos}),
                  "K": mkruns({r: [1, 1] for r in repos}, ok=False)}}
    rule = {"baseline": "A", "candidates": ["K"], "truncation_flag": 0.1,
            "delivery": {"K": {"min_read_fraction": 0.5, "read_marker": "/expertise/"}}}
    _, out = verdict.decide(rule, data)
    why = " ".join(out["K"][1])
    assert out["K"][0] == "DISCARD" and "truncation" in why and "delivery failure" in why


def test_power_rises_with_effect_and_n_and_null_is_quiet():
    rates = [0.0] * 6 + [0.5] * 6 + [1.0] * 2
    null = power.simulate(rates, 30, 2, 0.0, 0.05, 150)
    big = power.simulate(rates, 30, 2, 0.4, 0.05, 150)
    assert null < 0.1 < 0.5 < big
    assert power.simulate(rates, 60, 2, 0.15, 0.05, 150) >= power.simulate(rates, 15, 2, 0.15, 0.05, 150)


def test_calibrate_false_pass_rate_is_low_on_noise():
    rnd = random.Random(3)
    runs = {(f"r{i}", rep): {"found": int(rnd.random() < 0.4), "gold": 1} for i in range(25) for rep in (1, 2)}
    sign, ci, both = calibrate.rates(runs, 300, 0.05)
    assert both <= 0.10


def test_fixcheck_discrimination():
    pre = {"A": mkruns({"a": [1, 1], "b": [1, 0], "c": [0, 0]}), "K": mkruns({"a": [1, 1], "b": [1, 1], "c": [0, 0]})}
    post = {"A": mkruns({"a": [1, 1], "b": [0, 0], "c": [0, 0]}), "K": mkruns({"a": [0, 0], "b": [0, 0], "c": [0, 0]})}
    arms = fixcheck.summarize(pre, post)
    assert arms["A"]["a"] == (1.0, 1.0) and arms["K"]["b"] == (1.0, 0.0)
    n, res = fixcheck.compare(arms, "A", "K")
    assert n == 3 and res["discrimination"][0] > 0 and res["fix-tree alarm"][0] < 0


def test_oracle_note_names_files_not_lines():
    repo = next(iter(json.loads(suites.SUITES["cve"]["gold"].read_text())))
    note = run_eval.oracle_note("cve", repo)
    assert ".js" in note or ".py" in note or ".go" in note or ".ts" in note or ".rb" in note or ".php" in note
    assert not any(ch.isdigit() for ch in note.replace("v1", ""))


def test_arm_settings_distinguish_controls_and_commands():
    s = {run_eval.arm_setting(k, l, c, None) for k, l, c in [("A", None, None, ), ("O", None, None), ("H", None, None),
                                                              ("X", "a", "echo 1"), ("X", "a", "echo 2")]}
    assert len(s) == 5


def test_external_adapter_contract(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "x.py").write_text("print(1)\n")
    ok = 'echo \'{"findings":[{"file":"x.py","line":1}],"cost_usd":0.25}\''
    cwd, res, cost, st, _ = harness.generate_external(repo, ok, "sonnet", "p", "wide")
    f = res["findings"][0]
    assert st == "success" and cost == 0.25 and f["trace"] == [] and f["id"].startswith("F")
    cwd, res, cost, st, _ = harness.generate_external(repo, "echo not-json", "sonnet", "p", "wide")
    assert res is None and st.startswith("bad_output")
    cwd, res, cost, st, _ = harness.generate_external(repo, 'cat $HARNESS_SCHEMA_FILE >/dev/null; echo \'{"findings":[]}\'; exit 3',
                                                      "sonnet", "p", "wide")
    assert res == {"findings": []} and st == "exit_3"
    assert not list(cwd.parent.rglob("gold*"))


def test_extra_specs_are_merged(tmp_path, monkeypatch):
    monkeypatch.setattr(suites, "DATA", tmp_path)
    (tmp_path / "cve-specs-extra.json").write_text(json.dumps(
        [{"id": "new-one", "repo": "o/n", "sha": "abc", "ghsa": "GHSA-x", "sub": ".", "files": ["a.py"], "desc": "N is a thing."}]))
    ids = [s[0] for s in build_cve_corpus.all_specs()]
    assert "new-one" in ids and len(ids) == len(build_cve_corpus.SPECS) + 1


def test_verify_mode_is_part_of_the_cache_key():
    a = run_eval.arm_setting("A", None, None, None, True)
    b = run_eval.arm_setting("A", None, None, None, False)
    assert a != b
    assert suites.config_id("wide", "sonnet", None, None, a) != suites.config_id("wide", "sonnet", None, None, b)


def test_notes_wrapper_is_hashed(monkeypatch):
    before = suites.config_id("wide", "sonnet", None, None, "n")
    monkeypatch.setattr(harness, "NOTES_PREFIX", "different wrapper:\n{notes}\n\n")
    assert suites.config_id("wide", "sonnet", None, None, "n") != before
    # without notes the wrapper is irrelevant, so plain runs keep their ids
    monkeypatch.setattr(harness, "NOTES_PREFIX", "again:\n{notes}\n\n")
    assert suites.config_id("wide", "sonnet", None, None, None) == suites.config_id("wide", "sonnet", None, None, None)


@pytest.mark.parametrize("arm", ["A", "O", "H"])
def test_label_cannot_relabel_baseline_or_controls(arm, capsys):
    with pytest.raises(SystemExit):
        run_eval.main(["--suite", "wide", "--arms", arm, "--label", "K1"])
    assert "cannot be relabelled" in capsys.readouterr().err


def test_label_is_allowed_for_candidate_arms(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(run_eval, "one", lambda job: seen.setdefault("job", job) and ("x", "ok"))
    notes = tmp_path / "n.txt"
    notes.write_text("hi")
    run_eval.main(["--suite", "wide", "--arms", "N", "--label", "K1", "--notes-file", str(notes),
                   "--run-dir", str(tmp_path / "r"), "--reps", "1", "--workers", "1"])
    assert seen["job"][1] == "K1" and seen["job"][0] == "N"


def test_selftest_evaluate_passes_a_sound_setup_and_fails_a_blind_one():
    from harness_ablation import selftest
    repos = [f"r{i}" for i in range(14)]
    base = {r: [i % 2, i % 2] for i, r in enumerate(repos)}                    # half the repos hit
    sound = {"A": mkruns(base), "RAWX": mkruns(base),
             "O": mkruns({r: [1, 1] for r in repos}),
             "H": mkruns({r: [0, 0] for r in repos}, ok=False)}
    assert all(ok for _, ok, _ in selftest.evaluate(sound))
    blind = dict(sound, O=mkruns(base), H=mkruns(base))                          # controls change nothing
    res = {n: ok for n, ok, _ in selftest.evaluate(blind)}
    assert not res["oracle gain visible"] and not res["handicap harm visible"] and res["adapter ties baseline"]


def test_volmatch_separates_volume_from_quality():
    from harness_ablation import volmatch
    base = [("a", 1, [True] + [False] * 9), ("a", 2, [True] + [False] * 9), ("b", 1, [False] * 10)]
    quiet_but_hits = [("a", 1, [True]), ("a", 2, [True]), ("b", 1, [False])]     # 1 finding, still hits: better per finding
    c = volmatch.compare(base, quiet_but_hits)
    assert c["cand"] > c["base_matched"]
    noise_only = [("a", 1, [False]), ("a", 2, [False]), ("b", 1, [False])]
    assert volmatch.compare(base, noise_only)["cand"] <= volmatch.compare(base, noise_only)["base_matched"]


def test_staged_scratch_copy_is_removed_after_a_run(tmp_path, monkeypatch):
    repo = sorted(p for p in suites.SUITES["wide"]["corpus"].iterdir() if p.is_dir())[0]
    staged = {}

    def fake_generate(repo_dir, model, *a, **k):
        cwd = harness.stage(repo_dir)
        staged["root"] = cwd.parent
        return cwd, {"findings": []}, 0.0, "success", {"tools": {}, "skills": [], "reads": []}

    monkeypatch.setattr(harness, "generate", fake_generate)
    job = ("A", None, None, repo.name, 1, "sonnet", None, None, "wide", tmp_path, None, False)
    run_eval.one(job)
    assert staged["root"].exists() is False
    assert (tmp_path / f"A-{repo.name}-1.json").exists()


def test_verdict_names_significant_harm():
    repos = [f"r{i}" for i in range(14)]
    data = {"m": {"A": mkruns({r: [1, 1] for r in repos}), "K": mkruns({r: [0, 0] for r in repos})}}
    _, out = verdict.decide({"baseline": "A", "candidates": ["K"]}, data)
    assert out["K"][0] == "DISCARD" and any("significantly WORSE" in w for w in out["K"][1])


def test_verdict_rule_errors_are_readable_and_placebo_is_optional():
    repos = [f"r{i}" for i in range(12)]
    data = {"m": {"A": mkruns({r: [0, 0] for r in repos}), "K": mkruns({r: [1, 1] for r in repos})}}
    with pytest.raises(SystemExit) as e:
        verdict.decide({"baseline": "A", "placebo": "P", "candidates": ["K"]}, data)
    assert "'P'" in str(e.value) and "placebo" in str(e.value)
    rows, out = verdict.decide({"baseline": "A", "placebo": None, "candidates": ["K"], "_comment": "x"}, data)
    assert out["K"][0] == "KEEP" and "vs_placebo" not in rows[("K", "m")]
    with pytest.raises(SystemExit):
        verdict.decide({"baseline": "A", "candidates": ["Z"]}, data)


def test_verdict_warns_on_ragged_coverage(capsys):
    repos = [f"r{i}" for i in range(12)]
    data = {"m": {"A": mkruns({r: [0, 0] for r in repos}), "K": mkruns({r: [1, 1] for r in repos[:8]})}}
    verdict.decide({"baseline": "A", "candidates": ["K"]}, data)
    assert "different numbers of repos" in capsys.readouterr().err
