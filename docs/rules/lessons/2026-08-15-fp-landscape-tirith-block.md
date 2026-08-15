# Tirith gate false-positive landscape — 2026-08-15

- **Date:** 2026-08-15
- **Origin:** downgrades log analysis (4234 entries)
- **Proposed status:** REVIEW

## Summary

The Tirith gate (tirith 0.3.1) produces 4,199 `tirith_block` downgrades out of
4,234 total events = **99.2% of all downgrades** are blocks (vs other reasons
like `dynamic_word`, `local_write`).

This doc analyses which blocks are likely false positives vs genuine threats,
based on command patterns and the suppression logic in
`should_downgrade_for_command`. Each category below notes whether the
classification is verified or inferred from pattern analysis.

## Current suppression effectiveness

The FP suppression layer in `should_downgrade_for_command` / `is_suppressed_false_positive`
was measured at 47% effectiveness (335/713) at the time of the FP corpus commit
(db5efc93). The remaining 53% that still downgrade include:

| Finding | Count | Has suppression? | Gap |
|---------|-------|-----------------|-----|
| `pipe_to_interpreter` | 2134 (alone) + many combos | Partial — `all_interpreter_pipe_sinks_are_data_mode` | Backs off on ANY fetch word regardless of target trust |
| `curl_pipe_shell` | 435 (alone) + combos | Partial — trusted-host check | Only suppresses if ALL URL evidence trusted |
| `invalid_host_chars` | 335 (alone) | **NONE** | No entry in `suppresses_finding_for_command` |
| `plain_http_to_sink` | 182 (alone) + combos | Partial — trusted-host check | Same as curl_pipe_shell |
| `pip_to_interpreter+schemeless_to_sink` | 82 | Partial | `.all()` means both must suppress; schemeless only checks python -m |

## Breakdown by command class

| Command class | Count | % of FPs | Typical pattern |
|--------------|-------|----------|----------------|
| python3 | 3,035 | 72.3% | `curl localhost:PORT | python3 -c "..."` — API health checks, JSON parsing |
| node/bun/deno | 433 | 10.3% | Script execution, package management |
| curl | 273 | 6.5% | `curl http://192.168.x.x:PORT/` — internal API calls |
| bash/sh | 210 | 5.0% | `git remote add http://...`, script runners |
| git/gh | 105 | 2.5% | `git add`, `git push` to internal hosts |
| grep/rg | 46 | 1.1% | Searching code that mentions URLs |
| ls/find | 40 | 1.0% | Pipelines with python3 at the sink |
| cat|pipe | 28 | 0.7% | `cat file | python3 -c "..."` |

## Root cause: the fetch backstop prevents trusted-host suppression

`all_interpreter_pipe_sinks_are_data_mode()` calls `command_mentions_fetch(cmd)`
first. If ANY fetch word appears ANYWHERE in the command, it returns `false`
immediately — even when the fetch target is `localhost`, `127.0.0.1`, or a
trusted lab host.

Example suppressed by this:
```bash
curl -s http://localhost:8080/api/health | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])"
```
This has:
- A fetch on the left: `curl http://localhost:8080` → `command_mentions_fetch` returns true
- An explicit python3 `-c` data-mode program → `interpreter_args_are_data_mode` returns true
- No remote content (localhost is loopback)

Result: **NOT suppressed** — remains as a user-facing Ask prompt.

## Key gaps to fix

1. **`invalid_host_chars`** — 335 standalone entries, zero suppression at all.
   Tirith flags e.g. `http://192.168.1.1:3000/` with `invalid_host_chars` when
   the host contains non-standard characters. This is typical for internal
   network access. Add trusted-host checking.

2. **`pipe_to_interpreter` fetch backstop** — `command_mentions_fetch` blocks
   ALL suppression when a fetcher word appears, even for localhost targets.
   The `curl_pipe_shell` rule already has `fetch_head_targets_trusted()` that
   checks this — pipe_to_interpreter should reuse the same logic before
   giving up on the whole command.

3. **`.all()` combinator** — `is_suppressed_false_positive` requires EVERY
   finding to be suppressed. A single unsuppressed `invalid_host_chars` or
   `schemeless_to_sink` alongside an otherwise-suppressable `pipe_to_interpreter`
   keeps the downgrade. Mixed findings are common when the same command hits
   multiple rules.

## What to measure after a fix

Run `cargo test` and `scripts/extract-gate-corpus.py --replay` to verify
suppression rate changes. The two corpus guards are:

- `suppression_rate_does_not_regress` — floor against suppression breaking
- `genuinely_dangerous_commands_still_downgrade` — sentinels that must never
  be suppressed