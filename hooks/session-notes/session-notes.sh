#!/usr/bin/env bash
# Claude Code SessionEnd hook (matcher: clear). /clear ends the session with no
# live assistant turn, so a CLAUDE.md rule like "on compaction, append today's
# work to my notes" never runs. This hands the outgoing transcript to a headless
# `claude -p` that writes the note instead.
#
# The headless pass gets Read and Write only, under acceptEdits: no Bash, no
# bypassPermissions. mkdir and the current.md symlink are done here in plain
# shell, not by the agent. Register it as async so /clear isn't blocked.
#
# Environment:
#   NOTES_DIR          where daily notes live (default ~/Documents/notes)
#   NOTES_USAGE_RATES  pricing text for the usage line, e.g.
#                      "\$15/M input, \$75/M output"; omit to skip the dollar estimate
set -uo pipefail

input="$(cat)"
transcript=""
if command -v jq >/dev/null 2>&1; then
  transcript="$(printf '%s' "$input" | jq -r '.transcript_path // empty' 2>/dev/null || true)"
fi

[ -n "$transcript" ] || exit 0
[ -s "$transcript" ] || exit 0
command -v claude >/dev/null 2>&1 || exit 0

notes_dir="${NOTES_DIR:-$HOME/Documents/notes}"
mkdir -p "$notes_dir"
today="$(date +%Y-%m-%d)"
today_file="$notes_dir/$today.md"
transcript_dir="$(dirname "$transcript")"
log="${TMPDIR:-/tmp}/claude-session-notes-hook.log"

usage="give an approximate session token count (input+output)"
if [ -n "${NOTES_USAGE_RATES:-}" ]; then
  usage="$usage and a dollar-cost estimate at ${NOTES_USAGE_RATES}"
fi

prompt="Read the JSONL transcript at ${transcript} (an ending Claude Code session, cleared via /clear). If it reflects substantive work (not a trivial/empty/near-empty session), append a concise summary of that work to ${today_file} (create it if missing; match the structure and voice of any entries already in that file today). End the appended block with one line starting '**Usage estimate:**' that should ${usage}; if exact counts aren't visible in the transcript, give a bracketed range based on transcript length. If the session was trivial, make no edits at all. Work silently, do not ask questions, and use only the Read and Write tools."

claude -p "$prompt" \
  --permission-mode acceptEdits \
  --allowedTools "Read,Write" \
  --add-dir "$notes_dir" \
  --add-dir "$transcript_dir" \
  >"$log" 2>&1 || true

ln -sf "$today.md" "$notes_dir/current.md"

exit 0
