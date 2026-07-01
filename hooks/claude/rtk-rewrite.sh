#!/usr/bin/env bash
# rtk-hook-version: 4
# ContextCrawler Claude Code hook — thin delegator.
#
# This hook makes NO decisions of its own. It hands the raw PreToolUse payload
# on stdin to the Rust binary, which is the single source of truth for schema
# selection, security gating (Tirith + supply-chain), and the permission
# verdict (allow / ask / deny / rewrite) — see src/hooks/hook_cmd.rs.
#
# Keeping every decision in one tested place removes the whole class of
# schema/gating bugs that recurs when the logic is duplicated in bash (the
# #2493 council review found three successive fail-open holes in the old
# bash implementation). To change rewrite or gate behaviour, edit the Rust
# source — not this file.
#
# Requires: contextcrawler on PATH. (No jq — the binary parses the payload.)

if ! command -v contextcrawler &>/dev/null; then
  echo "[contextcrawler] WARNING: contextcrawler is not installed or not in PATH. Hook cannot rewrite commands. Install: https://github.com/thehoff/contextcrawler#install" >&2
  # Fail OPEN only on a MISSING binary: the proxy is a token-saving optimisation,
  # not a security boundary the user opted into at this layer, so never block the
  # workflow just because the tool is absent (fallback-pattern rule). The binary
  # itself fails CLOSED on malformed/ambiguous payloads once present.
  exit 0
fi

# Delegate the entire decision to the Rust hook handler. It reads the payload
# from stdin and writes the PreToolUse hook JSON (or nothing, to pass through)
# to stdout, always exiting 0 — the verdict travels in the JSON, not the code.
exec contextcrawler hook claude
