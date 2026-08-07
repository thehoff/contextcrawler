# Claude Code Hooks

> Part of [`hooks/`](../README.md) — see also [`src/hooks/`](../../src/hooks/README.md) for installation code

## Specifics

- Shell-based `PreToolUse` hook -- requires `jq` for JSON parsing
- Returns `updatedInput` JSON for transparent command rewrite (agent doesn't know RTK is involved)
- Exits silently (exit 0) on any failure: jq missing, contextcrawler missing, rewrite returns no match
- No version guard - the hook only requires `contextcrawler` (with the `rewrite` subcommand) on PATH
- `rtk-awareness.md` is a slim 10-line instructions file embedded into CLAUDE.md by `contextcrawler init`

## Testing

```bash
# Run the full test suite (60+ assertions)
bash hooks/test-rtk-rewrite.sh

# Test against a specific hook path
HOOK=/path/to/rtk-rewrite.sh bash hooks/test-rtk-rewrite.sh

# Enable audit logging during testing
RTK_HOOK_AUDIT=1 RTK_AUDIT_DIR=/tmp bash hooks/test-rtk-rewrite.sh
```
