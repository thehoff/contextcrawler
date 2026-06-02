# Working with the security gate

Practical guide for when the contextcrawler security gate (Tirith pairing)
blocks a command. For what the gate is, how it is wired, and its
environment knobs, see the "Security gate" section of the top-level
`README.md`.

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
