#!/usr/bin/env bash
# Adapter example: the raw model through `claude -p`, i.e. what built-in arm A does, as an external
# harness. Use it as the template for your own, and as a self-test: it must tie with arm A.
# Contract: runs in a scratch copy of the repo; HARNESS_* env vars are set; print one JSON object
# {"findings": [...], "cost_usd": N} on stdout.
set -euo pipefail
claude -p --model "$HARNESS_MODEL" --setting-sources project --strict-mcp-config \
  --no-session-persistence --output-format json --disable-slash-commands \
  --json-schema "$(cat "$HARNESS_SCHEMA_FILE")" \
  --allowedTools Read Grep Glob --disallowedTools Bash --max-budget-usd 1.50 \
  "$HARNESS_PROMPT" |
  python3 -c '
import json, sys
r = json.load(sys.stdin)
print(json.dumps({"findings": (r.get("structured_output") or {}).get("findings", []),
                  "cost_usd": r.get("total_cost_usd", 0.0)}))
'
