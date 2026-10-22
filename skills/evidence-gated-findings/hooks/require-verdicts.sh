#!/usr/bin/env bash
# Stop hook: block the final answer while any candidate finding lacks a verdict.
# Candidates live in $CWD/findings/*.json; each needs .verdict set by the verifier.
# Register under hooks.Stop in .claude/settings.json. Exit 2 blocks; exit 0 allows.
set -u
input=$(cat)
cwd=$(printf '%s' "$input" | jq -r '.cwd // empty')
[ -n "$cwd" ] && [ -d "$cwd/findings" ] || exit 0
# Do not loop forever: if we already blocked once this turn, let it through.
[ "$(printf '%s' "$input" | jq -r '.stop_hook_active // false')" = "true" ] && exit 0
pending=$(jq -r 'select((.verdict // "") | IN("CONFIRMED","REFUTED","UNVERIFIABLE") | not) | input_filename' \
  "$cwd"/findings/*.json 2>/dev/null)
if [ -n "$pending" ]; then
  echo "Unverified candidate findings (run the verifier, see the evidence-gated-findings skill):" >&2
  printf '%s\n' "$pending" >&2
  exit 2
fi
exit 0
