#!/usr/bin/env python3
"""Adapter example: a non-LLM harness (Semgrep OSS rules) in the framework's findings schema.

Sends no code anywhere (metrics off; rules are fetched from the registry). Needs `semgrep` on PATH.
Run with: ablate run --suite cve --arm-cmd semgrep='python3 $HARNESS_LAUNCH_DIR/examples/adapters/semgrep_oss.py' --no-verify
"""
import json
import subprocess
import sys

CONFIG = "p/security-audit"


def main():
    p = subprocess.run(["semgrep", "scan", "--config", CONFIG, "--json", "--quiet", "--metrics=off",
                        "--timeout", "30", "."], capture_output=True, text=True)
    try:
        results = json.loads(p.stdout).get("results", [])
    except ValueError:
        print(json.dumps({"findings": []}))
        sys.exit(1)
    findings = []
    for i, r in enumerate(results, 1):
        line = r["start"]["line"]
        findings.append({"id": f"S{i}", "file": r["path"], "line": line,
                         "claim": r["extra"].get("message", "")[:300], "source": "", "sink": r["check_id"],
                         "trace": [{"file": r["path"], "line": line, "note": r["check_id"]}],
                         "guards_checked": ""})
    print(json.dumps({"findings": findings, "cost_usd": 0.0}))


if __name__ == "__main__":
    main()
