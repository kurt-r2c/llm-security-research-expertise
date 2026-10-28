# session-notes

Keeps a daily work log in `~/Documents/notes/YYYY-MM-DD.md`, with `current.md` pointing at today's
file. There are two halves, one for each way a Claude Code session loses its context.

## Compaction: a CLAUDE.md rule

A compaction still has a live assistant turn, so a rule in `~/.claude/CLAUDE.md` is enough:

```markdown
- on compaction, append today's work to `~/Documents/notes/YYYY-MM-DD.md` (one file per calendar
  day) and `ln -sf YYYY-MM-DD.md ~/Documents/notes/current.md`. End the appended block with a
  one-line **Usage estimate:** showing approximate session tokens (input + output) and a dollar
  cost estimate. If exact counts aren't visible, give a bracketed range based on conversation length.
```

To keep the log in front of every session, add `@~/Documents/notes/current.md` to the same file.

## /clear: the hook

`/clear` ends the session with no assistant turn, so the rule never fires. `session-notes.sh` runs
on `SessionEnd` with matcher `clear` and gives the outgoing transcript to a headless `claude -p`
that can only Read and Write.

```bash
mkdir -p ~/.claude/hooks
cp session-notes.sh ~/.claude/hooks/ && chmod +x ~/.claude/hooks/session-notes.sh
```

Then add this to `~/.claude/settings.json`, using the absolute path to the script:

```json
{
  "hooks": {
    "SessionEnd": [
      {
        "matcher": "clear",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/.claude/hooks/session-notes.sh",
            "timeout": 180,
            "async": true,
            "statusMessage": "Appending today's work to notes before clear..."
          }
        ]
      }
    ]
  }
}
```

Requires `jq` and `claude` on `PATH`. Set `NOTES_DIR` to log somewhere else, and
`NOTES_USAGE_RATES` (for example `"\$15/M input, \$75/M output"`) to get a dollar figure on the
usage line. The headless run's output goes to `$TMPDIR/claude-session-notes-hook.log`.

The transcript goes to the same model API as the session it came from, and nowhere else.
