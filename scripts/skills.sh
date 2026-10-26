#!/usr/bin/env bash
# Install, update, uninstall and report the skills under skills/ for whichever
# agent runtimes are present. Driven by the Makefile; see `make help`.
#
# Detection: a runtime counts as present when its binary is on PATH, its config
# directory exists, or (macOS) its app bundle is installed. Each runtime maps to
# its documented user-level skills root. Any other well-known root that already
# holds a */SKILL.md is included too. Override everything with ROOTS="dir1 dir2".
#
# Safety: gitignored files (venvs, eval runs) are never installed. Each installed skill carries a
# marker file; uninstall and update only touch directories that have it (or
# symlinks pointing back into this repo). A same-named skill that is not ours,
# or another skill with the same frontmatter name, is skipped unless FORCE=1.
#
# Compatible with macOS bash 3.2: no associative arrays, no mapfile.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
SRC="$REPO/skills"
MARKER=".installed-by-llm-security-research-expertise"
MODE=${MODE:-copy}        # copy | link
FORCE=${FORCE:-0}
DRY_RUN=${DRY_RUN:-0}
H=$HOME

# runtime|binaries (comma)|config dirs (comma)|macOS app|skills root
# Roots per vendor docs; ~/.agents/skills is the cross-agent location read by
# Codex, Copilot, Gemini CLI, Goose and OpenCode, so they share one install.
RUNTIMES="
claude-code|claude|$H/.claude|Claude.app|$H/.claude/skills
cursor|cursor,cursor-agent|$H/.cursor|Cursor.app|$H/.cursor/skills
codex|codex|$H/.codex|Codex.app|$H/.agents/skills
copilot|copilot|$H/.copilot||$H/.agents/skills
gemini|gemini|$H/.gemini||$H/.agents/skills
goose|goose|$H/.config/goose|Goose.app|$H/.agents/skills
opencode|opencode|$H/.config/opencode||$H/.agents/skills
windsurf|windsurf|$H/.codeium/windsurf,$H/.windsurf|Windsurf.app|$H/.codeium/windsurf/skills
openclaw|openclaw|$H/.openclaw||$H/.openclaw/skills
"

# Roots checked for existing SKILL.md files even if no runtime was detected.
WELL_KNOWN="$H/.claude/skills $H/.agents/skills $H/.cursor/skills $H/.codex/skills
$H/.copilot/skills $H/.gemini/skills $H/.config/opencode/skills
$H/.config/goose/skills $H/.codeium/windsurf/skills $H/.openclaw/skills"

log() { printf '%s\n' "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then log "  [dry-run] $*"; else "$@"; fi; }

has_any_bin() {
  local IFS=,
  for b in $1; do command -v "$b" >/dev/null 2>&1 && return 0; done
  return 1
}
has_any_dir() {
  local IFS=,
  for d in $1; do [ -d "$d" ] && return 0; done
  return 1
}

# Prints "runtime<TAB>root<TAB>evidence" for each detected runtime.
detect() {
  echo "$RUNTIMES" | while IFS='|' read -r rt bins dirs app root; do
    [ -n "$rt" ] || continue
    ev=""
    has_any_bin "$bins" && ev="bin"
    has_any_dir "$dirs" && ev="${ev:+$ev,}config"
    [ -n "$app" ] && [ -d "/Applications/$app" ] && ev="${ev:+$ev,}app"
    [ -n "$ev" ] && printf '%s\t%s\t%s\n' "$rt" "$root" "$ev"
  done
  for r in $WELL_KNOWN; do
    ls "$r"/*/SKILL.md >/dev/null 2>&1 && printf '%s\t%s\t%s\n' "existing-skills" "$r" "SKILL.md"
  done
}

roots() {
  if [ -n "${ROOTS:-}" ]; then
    for r in $ROOTS; do echo "$r"; done
  else
    detect | cut -f2 | awk '!seen[$0]++'
  fi
}

# Frontmatter `name:` of a SKILL.md, falling back to the directory name.
skill_name() {
  n=$(awk 'NR==1 && $0!="---"{exit} NR>1 && $0=="---"{exit} /^name:/{sub(/^name:[ \t]*/,""); gsub(/["\047]/,""); print; exit}' "$1/SKILL.md")
  if [ -n "$n" ]; then echo "$n"; else basename "$1"; fi
}

# Top-level skills: skills/<dir>/SKILL.md. Nested SKILL.md files ship inside
# their parent (security-research reads its domain skills from subdirs).
skills() { for d in "$SRC"/*/; do [ -f "$d/SKILL.md" ] && echo "${d%/}"; done; }

ours() {  # is $1 an install made by this script?
  [ -f "$1/$MARKER" ] && return 0
  [ -L "$1" ] && case "$(readlink "$1")" in "$SRC"/*) return 0 ;; esac
  return 1
}

# Another skill in the root (not ours) declaring the same frontmatter name.
name_clash() {
  root=$1 name=$2 dest=$3
  for other in "$root"/*/; do
    other=${other%/}
    [ "$other" = "$dest" ] && continue
    [ -f "$other/SKILL.md" ] || continue
    ours "$other" && continue
    [ "$(skill_name "$other")" = "$name" ] && { echo "$other"; return 0; }
  done
  return 1
}

copy_tracked() {  # copy non-ignored files, minus vulnerable eval corpora
  src=$1 dest=$2
  rel=${src#"$REPO"/}
  tmp=$(mktemp -d)
  if git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
    # Tracked plus untracked-but-not-ignored, so .venv, eval runs and other
    # gitignored output stay out. Skip tracked files deleted from the tree.
    (cd "$REPO" && git ls-files -z --cached --others --exclude-standard -- "$rel" |
      while IFS= read -r -d '' f; do [ -f "$f" ] && printf '%s\0' "$f"; done |
      xargs -0 tar -cf -) | tar -xf - -C "$tmp"
  else
    (cd "$REPO" && tar -cf - --exclude .venv --exclude __pycache__ --exclude runs "$rel") | tar -xf - -C "$tmp"
  fi
  rm -rf "$tmp/$rel/eval/corpus"*
  if [ ! -f "$tmp/$rel/SKILL.md" ]; then
    rm -rf "$tmp"; log "  FAIL  nothing to copy from $src"; return 1
  fi
  rm -rf "$dest"
  mv "$tmp/$rel" "$dest"
  rm -rf "$tmp"
  rev=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
  printf 'source=%s\ncommit=%s\ninstalled=%s\n' "$src" "$rev" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$dest/$MARKER"
}

install_into() {
  root=$1
  run mkdir -p "$root"
  for s in $(skills); do
    name=$(skill_name "$s")
    dest="$root/$name"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
      if ! ours "$dest" && [ "$FORCE" != 1 ]; then
        log "  skip  $dest exists and was not installed by this repo (FORCE=1 to replace)"; continue
      fi
    fi
    if clash=$(name_clash "$root" "$name" "$dest") && [ "$FORCE" != 1 ]; then
      log "  skip  $name: $clash already declares name '$name' (FORCE=1 to install anyway)"; continue
    fi
    if [ "$MODE" = link ]; then
      run rm -rf "$dest"; run ln -s "$s" "$dest"
    elif [ "$DRY_RUN" = 1 ]; then
      log "  [dry-run] copy $s -> $dest"
    else
      copy_tracked "$s" "$dest" || continue
    fi
    log "  ok    $dest"
  done
}

uninstall_from() {
  root=$1
  for s in $(skills); do
    dest="$root/$(skill_name "$s")"
    [ -e "$dest" ] || [ -L "$dest" ] || continue
    if ours "$dest"; then run rm -rf "$dest"; log "  removed $dest"
    else log "  left  $dest (not installed by this repo)"; fi
  done
}

status_of() {
  root=$1
  for s in $(skills); do
    dest="$root/$(skill_name "$s")"
    if [ -L "$dest" ] && ours "$dest"; then st="linked"
    elif [ -f "$dest/$MARKER" ]; then st="copied @ $(sed -n 's/^commit=//p' "$dest/$MARKER")"
    elif [ -e "$dest" ]; then st="FOREIGN (not ours)"
    else st="absent"; fi
    clash=$(name_clash "$root" "$(skill_name "$s")" "$dest" || true)
    log "  $(skill_name "$s"): $st${clash:+  [name clash: $clash]}"
  done
}

cmd=${1:-help}
case "$cmd" in
  detect)
    detect | while IFS="$(printf '\t')" read -r rt root ev; do printf '%-16s %-40s %s\n' "$rt" "$root" "$ev"; done ;;
  install|uninstall|status)
    rs=$(roots)
    [ -n "$rs" ] || { log "No agent runtime detected. Set ROOTS=\"~/.claude/skills ...\"."; exit 1; }
    for r in $rs; do
      log "$r"
      case "$cmd" in install) install_into "$r" ;; uninstall) uninstall_from "$r" ;; status) status_of "$r" ;; esac
    done ;;
  *) log "usage: $0 detect|install|uninstall|status"; exit 2 ;;
esac
