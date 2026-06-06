# Module audit — `src/hooks/tirith_gate.rs`

Internal code review. 149 lines. Companion to the supply-chain gate
audit. Subprocess-based gate that invokes `tirith check` and parses
the verdict.

## What it does

Subprocess-calls `tirith check --format json --non-interactive --no-daemon
-- <cmd>` on the auto-allow hook path. Parses the JSON verdict
(`action: "allow"` / `"block"`). Returns a `Verdict` that the caller
uses to downgrade an upstream `Allow` to `Ask`.

Trust placement: AGPL Tirith stays out-of-process (no static linking).
ContextCrawler's MIT-licensed wrapper is the only thing we ship; we
just spawn Tirith as a subprocess.

## Verdict surface

| Variant | When | Downstream effect |
|---|---|---|
| `Allow` | Tirith said `action: "allow"` | Caller continues normally |
| `Block { tirith_json }` | Tirith said `action: "block"` | Caller downgrades Allow → Ask; logs to `downgrades.jsonl` |
| `Unavailable` | Tirith binary missing, errored, or unrecognized verdict | Caller's policy: fail-open (default) or fail-closed (`CONTEXTCRAWLER_TIRITH_REQUIRED=1`) |

## Good practices observed (no change needed)

- **Subprocess-only invocation.** AGPL stays out-of-process. ✓
- **Structural JSON parse.** Uses `serde_json::from_str` not substring
  match. Comment explicitly calls out why (line 64).
- **Flag isolation.** `--` separator before the user command prevents
  the agent's `cmd` from being interpreted as Tirith flags.
- **`--non-interactive`** prevents Tirith from prompting (would
  deadlock the hook).
- **`--no-daemon`** prevents Tirith from spawning a persistent
  background process during a one-shot check.
- **Soft opt-out** via `CONTEXTCRAWLER_TIRITH_DISABLED=1` for debugging.
- **Fail-open by default**, fail-closed available via
  `CONTEXTCRAWLER_TIRITH_REQUIRED=1`. Two-tier trust model surfaces
  cleanly in `should_downgrade`.
- **JSON escape** for log lines (`json_escape` at line 133) handles
  the standard escapes plus `\u00XX` for control chars. Correct.
- **Best-effort logging.** Directory creation failure or write failure
  is silently dropped — no crash on disk-full.
- **Stable reason strings** in `should_downgrade` (`tirith_block`,
  `tirith_required_unavailable`). Easy to grep `downgrades.jsonl` for.

## Findings

### F-01: No subprocess timeout (MEDIUM)

**Location:** `check` at line 46.

```rust
let output = Command::new(&bin)
    .args([...])
    .arg(cmd)
    .output();
```

`Command::output()` has **no timeout**. If `tirith` hangs (deadlocks
on a malformed input, blocked DNS, spinning loop in a buggy rule),
the caller's `permissionDecision: allow` hook blocks indefinitely.
The host agent's PreToolUse handler will time out from the agent
side eventually, but during that interval the agent UI is frozen
waiting.

The supply-chain gate (`supply_chain_gate.rs`) sets an 8s timeout on
its HTTP calls. The tirith gate should match.

**Recommendation:** Use the `wait-timeout` crate (~150 LoC, well-
maintained, std-process based) and cap at 5–8s:

```rust
use std::time::Duration;
use wait_timeout::ChildExt;

let mut child = Command::new(&bin)
    .args([...]).arg(cmd)
    .stdout(Stdio::piped()).stderr(Stdio::piped())
    .spawn()?;
match child.wait_timeout(Duration::from_secs(8)) {
    Ok(Some(status)) => { /* read piped stdout */ }
    Ok(None) => {
        let _ = child.kill();
        return Verdict::Unavailable;  // timeout → fail open
    }
    Err(_) => return Verdict::Unavailable,
}
```

Alternative: spawn a watchdog thread that calls `child.kill()` after
N seconds, then `child.wait()` synchronously. Pure-std, no new crate.

### F-02: No stdout size cap (LOW)

**Location:** `check` line 62.

```rust
let stdout = String::from_utf8_lossy(&output.stdout).to_string();
```

`Command::output()` reads child stdout to EOF with no size cap. A
malicious or compromised tirith binary could emit gigabytes and OOM
us. Real risk is low (tirith is a trusted tool), but cheap defence.

**Recommendation:** When switching to the spawn+timeout pattern
above, read piped stdout via `.take(MAX_BYTES).read_to_end()` like
the supply-chain gate does (`HTTP_MAX_BYTES = 64 MB` — 1–4 MB is
plenty for a tirith verdict JSON).

### F-03: Fallback binary path enables silent override (INFO)

**Location:** `check` lines 31–43.

```rust
let bin = if which::which("tirith").is_ok() {
    "tirith".to_string()
} else {
    let cargo_bin = home.join(".cargo/bin/tirith");
    ...
};
```

If `tirith` is not on `$PATH` but `~/.cargo/bin/tirith` exists,
that's used. An attacker who can write to `~/.cargo/bin/` can
install a fake `tirith` that always returns `{"action":"allow"}` and
the gate silently degrades to no-op.

This is a "compromised local account" scenario which sits **outside
our documented threat model** — once your `~/.cargo/bin/` is
writable by hostile code, all bets are off (they can also replace
`contextcrawler` itself). But the integrity-check pattern used for
the agent rewrite hook (SHA-256 pinning in `hooks/integrity.rs`)
isn't applied to tirith.

**Recommendation:** Document the trust assumption in
`docs/security/THREAT_MODEL.md` (currently mentions hook integrity
but not tirith binary integrity). Optionally: pin a SHA-256 of the
expected tirith binary at `init` time and verify on every check.
Adds operational friction — tirith updates would need re-pinning.
Probably not worth it for a defence-in-depth gate, but call it out.

### F-04: `tirith_json` in log is not re-escaped (LOW)

**Location:** `log_downgrade` line 107.

```rust
format!(
    r#"{{"ts":"{}","reason":"{}","cmd":{},"tirith":{}}}"#,
    timestamp,
    reason,
    json_escape(cmd),
    json.trim(),       // <-- tirith's raw JSON, NOT re-escaped
)
```

`tirith_json` is inserted as-is into the line. If tirith produces
malformed JSON, our `downgrades.jsonl` becomes one corrupt line
(downstream JSON parsers will fail on that line and skip it). If
tirith produces correctly-formed JSON with embedded newlines
(pretty-printed), the JSONL format breaks (a single tirith record
spans multiple lines).

Real impact: garbled `gain --history` / `security log` output, not
a security issue. But: a malicious tirith with literal newlines
inside its JSON output could inject a fake-looking log line.

**Recommendation:** Re-parse-and-re-serialize the tirith JSON in
`log_downgrade` before embedding, or strip newlines from `json`
before formatting. `serde_json::to_string(&serde_json::from_str(&json)?)`
gives a canonical single-line form.

### F-05: stdin / stderr unhandled (INFO)

**Location:** `check` line 46.

`Command::new(&bin).args(...).output()` inherits stdin (from the
caller, which is the contextcrawler binary). For Tirith, stdin being a pipe
from the agent's hook payload could leak whatever's on the agent's
stdin into Tirith's process. Real risk: low — Tirith doesn't read
stdin in `--non-interactive` mode — but explicit `Stdio::null()` is
defence in depth.

Stderr is also inherited, so a verbose Tirith would print to the
hook's stderr (= the agent's tool-call stderr buffer). Visible to
the user, fine.

**Recommendation:** `.stdin(Stdio::null())` and capture `stderr`
explicitly for the downgrade log (handy when diagnosing Tirith
errors inside `gain --history`).

## Test coverage

| Surface | Coverage |
|---|---|
| `check` happy path (allow / block) | Not seen in this file's test mod |
| `check` Unavailable variants | Not seen |
| `json_escape` | Not seen — straightforward; could fuzz |
| `log_downgrade` jsonl format | Not seen |
| Env-var opt-outs | Not seen |
| Timeout behaviour (after F-01 fix) | Future |

**Recommendation:** Add test coverage in a follow-up branch. Highest
priority: a fake `tirith` script (or a mock-binary fixture) that
simulates the four paths (allow / block / hang / missing).

## Summary

149 lines, well-scoped, single-purpose. Five findings; F-01
(missing timeout) is the only one that's **production-relevant** —
a hung tirith blocks the agent's hook indefinitely until the agent
gives up. The rest are LOW/INFO hardening.

Threat-model alignment: needs an explicit mention of tirith binary
trust assumption in `docs/security/THREAT_MODEL.md`.
