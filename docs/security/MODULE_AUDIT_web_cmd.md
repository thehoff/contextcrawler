# Module audit — `Commands::Web` dispatch + `src/cmds/cloud/web_cmd.rs`

Internal code review of the `contextcrawler web <url>` command path.

## What it does

- `Commands::Web { url: String }` (src/main.rs line 787) takes a
  positional URL argument.
- Dispatch (src/main.rs line 2514) shells out to `curl -s -L <url>`,
  captures stdout, runs the response through `web_cmd::is_html` →
  `web_cmd::extract_content` (HTML chrome stripping), prints the
  filtered result.
- The HTML extraction itself (web_cmd.rs, 472 lines) is pure
  parsing — no network, no I/O. That part is fine; audit focus
  below is the dispatch.

## Good practices observed

- `core::utils::resolved_command("curl")` resolves curl via the same
  PATH lookup the rest of contextcrawler uses. Consistent.
- `-s -L` (silent + follow redirects) — sensible defaults.
- HTML extraction is offline and well-tested (10 inline tests:
  preserve/strip nav, footer, scripts, code blocks, tables, alt
  text, ad/social elements). Pure transform.
- HTML extraction uses `scraper` (HTML5-spec parser) — no regex
  parsing of attacker-controlled markup.

## Findings

### F-01: file:// scheme reads local files (HIGH)

**Location:** src/main.rs line 2517.

```rust
cmd.args(["-s", "-L", &url]);
```

`url` is whatever the agent / user typed. curl supports `file://`
scheme by default. So:

```
contextcrawler web file:///etc/passwd
contextcrawler web file:///home/user/.aws/credentials
contextcrawler web file:///home/user/.ssh/id_rsa
```

…all read local files and emit them via stdout straight into the
agent's context. An agent prompt-injection that says "fetch this
file://" payload would silently leak whatever the user has read
permission for.

**Recommendation:** Validate the scheme to an allow-list (`http`,
`https`) before passing to curl. Use the `url` crate (already
transitive via `ureq`) or a manual prefix check:

```rust
let parsed = url::Url::parse(&url).context("invalid URL")?;
match parsed.scheme() {
    "http" | "https" => {},
    other => anyhow::bail!("unsupported scheme: {} — only http/https allowed", other),
}
```

### F-02: SSRF — link-local / private address ranges (HIGH)

**Location:** same.

Even with http/https only, the URL can target:

- `http://169.254.169.254/...` — AWS / GCP / Azure metadata service,
  returns IAM creds, instance identity, user-data.
- `http://localhost:N/...` — local services bound to loopback
  (databases, internal admin endpoints).
- `http://10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12` — internal
  RFC1918.

With `-L` (follow redirects), even an http://public.example/ URL can
30x-redirect into one of these — the user-supplied URL is "safe"
but the final hop isn't.

**Recommendation:** After URL parse, resolve the host and reject if
the resolved IP is in the link-local, loopback, or RFC1918 ranges.
Use `std::net::IpAddr::is_loopback`, `is_private`, `is_link_local`
helpers. For redirects, either disable them (`-L` becomes `--no-location`)
or do DNS pre-resolve and verify each hop manually — complex. The
simplest defensible fix is to drop `-L` and require the agent / user
to follow redirects explicitly.

### F-03: No request timeout (MEDIUM)

**Location:** src/main.rs line 2518.

```rust
let output = cmd.output().context("Failed to fetch URL with curl")?;
```

`cmd.output()` has no timeout, and curl itself isn't given
`--max-time`. A slow / hanging endpoint blocks the agent's hook
indefinitely. Same class as the tirith F-01.

**Recommendation:** Add `--max-time 30` (or shorter) to the curl
args. Also apply a wall-clock timeout via `wait-timeout` (same crate
we added for the tirith gate) as defence in depth.

### F-04: No response size cap (MEDIUM)

**Location:** src/main.rs line 2524.

```rust
let raw = String::from_utf8_lossy(&output.stdout).to_string();
```

`output.stdout` is whatever curl received. A 10 GB response would
OOM us. Mitigated weakly by curl having no default size cap either.

**Recommendation:** Add `--max-filesize 67108864` (64 MB) to the
curl args, matching the supply-chain gate's HTTP_MAX_BYTES.
Alternatively, spawn curl with stdout piped and use
`.take(MAX).read_to_end()` like the tirith gate does.

### F-05: curl stderr emitted without strip_ansi (LOW)

**Location:** src/main.rs line 2520-2521.

```rust
eprintln!("FAILED: curl {}", stderr.trim());
```

curl's stderr can contain ANSI escapes (rare but possible on some
TTY-detection paths). This is the same class as the raw-emit sweep
on the `feat/sec-raw-emit-sweep` branch.

**Recommendation:** Wrap with `strip_ansi(&stderr).trim()` once the
raw-emit-sweep branch merges into develop.

### F-06: Output piped verbatim to stdout, no length cap (LOW)

**Location:** src/main.rs line 2530.

```rust
println!("{}", filtered);
```

After HTML extraction, `filtered` might still be large. There's no
truncation — entire page content reaches the LLM. Token-cost concern
more than security, but `CTXCRL_TEE_DIR` isn't applied to the web
command either. Not a security finding; UX/cost note.

### F-07: `url` positional arg vs flag injection (INFO)

**Location:** Web command definition, src/main.rs line 787.

```rust
Web {
    url: String,
},
```

clap treats `url` as positional. `contextcrawler web --evil` would
be rejected by clap (unknown flag), but `contextcrawler web -- --evil`
or `contextcrawler web "--evil"` would pass through. curl then
interprets `--evil` as a flag.

`-- --evil` clap would treat as positional `--evil`. curl gets
`["-s", "-L", "--evil"]` — fails with curl: option `--evil`: is
unknown — but a real flag like `-K /etc/passwd` (read config from
file) is a real attack vector if reachable.

In practice clap's `trailing_var_arg = false` (default) prevents
flag-look-alike positionals from being accepted unless `-- ` is
used first by the caller. Limited attack surface, but worth a `--`
separator before `&url`:

```rust
cmd.args(["-s", "-L", "--", &url]);
```

That tells curl "no more flags after this point", so any leading-dash
URL is treated as data. curl supports `--` as flag terminator.

## Test coverage

| Surface | Coverage |
|---|---|
| HTML extraction (`web_cmd.rs`) | 10 inline tests — strong |
| URL scheme validation | None — file:// not tested |
| SSRF guard | None |
| Timeout behaviour | None |
| Response size cap | None |
| curl stderr emit | None |

**Recommendation:** Add tests for each of F-01..F-04 once fixes
land. Particularly easy: feed `file:///` and assert refusal.

## Summary

Six findings on the dispatch path:

- **F-01 (HIGH)** — `file://` scheme reads local files. Real attack
  vector for prompt-injection-driven data exfiltration. Cheap fix.
- **F-02 (HIGH)** — SSRF via link-local / RFC1918 addresses. Real
  attack vector against cloud workloads (AWS / GCP metadata
  service). Moderately invasive fix.
- **F-03 (MEDIUM)** — no request timeout. Hung agent hook.
- **F-04 (MEDIUM)** — no response size cap. OOM.
- **F-05 (LOW)** — curl stderr emitted without strip_ansi.
- **F-06 (LOW)** — output not length-capped. UX/cost.
- **F-07 (INFO)** — `--` separator before URL hardens flag-injection
  surface even though clap mostly blocks it.

F-01 and F-02 are the prompt-injection-relevant ones — both should
land in `v0.1.7` or `v0.2.0`. The HTML extraction code itself is
clean; the gap is at the dispatch / fetch boundary.

Threat-model alignment: the web command should be called out under
"Surface 2: tool output → LLM context injection" since its output
is exactly that — a third-party-controlled blob entering the agent's
context.
