# Security Policy

## Reporting a Vulnerability in ContextCrawler

If you discover a security vulnerability in ContextCrawler, please report it
**privately** — do not file a public issue.

### Preferred channel: GitHub Security Advisories

Open a private security advisory at:

**<https://github.com/thehoff/contextcrawler/security/advisories/new>**

GitHub will route the report directly to the maintainer and start a private
collaboration thread.

### Fallback channel: email

If you can't use GitHub's advisory flow, email:

**contextcrawler@thehoff.id.au**

Please include:

- A clear description of the issue and its impact
- Reproduction steps (a minimal PoC if possible)
- The affected version(s) — `contextcrawler --version`
- Your preferred attribution name / handle for the eventual public advisory

### What to expect

- **Acknowledgment**: within 72 hours (often faster).
- **Triage**: a few business days after acknowledgment. I'll let you know
  whether the report is in scope, what the severity looks like, and the
  rough fix timeline.
- **Coordinated disclosure**: 90-day embargo by default. I'll work with
  you on a public advisory and credit you (with permission) once a fix is
  available.

### Please do NOT

- Open a public GitHub issue describing the vulnerability.
- Disclose the issue on social media, forums, or a public blog before a
  coordinated disclosure has happened.
- Run automated scans or pentest tools against third parties' deployments
  of ContextCrawler without explicit permission.

---

## Upstream vulnerabilities

ContextCrawler is a downstream distribution of
[`rtk-ai/rtk`](https://github.com/rtk-ai/rtk). If a vulnerability looks
like it lives in upstream contextcrawler's code (anywhere outside the
`// ===== contextzip-downstream =====` sentinel blocks), please **also**
report it to upstream's security channel — that fix benefits the broader
contextcrawler ecosystem and ContextCrawler will inherit it on the next rebase.

Upstream contact details are in
[`docs/upstream/RTK_README.md`](docs/upstream/RTK_README.md) and the
upstream repo's own `SECURITY.md`.

---

## Tirith integration

ContextCrawler ships an optional pre-execution gate that calls
[`tirith`](https://github.com/sheeki03/tirith) as a subprocess. Tirith's
own security disclosures are handled by the Tirith project; if your
report concerns Tirith specifically, please route to upstream tirith.

If the issue is in *how ContextCrawler integrates with Tirith* (e.g., a
way to bypass our gate), that's in scope here — report via the channels
above.

---

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |
| < 0.1   | ❌ (pre-release; do not use) |

---

## Scope

In scope:

- The `contextcrawler` binary and any of its subcommands
- Hook scripts under `hooks/`
- Build / install / update paths
- The Tirith pre-execution gate logic (anything inside the
  `// ===== contextzip-downstream =====` sentinel blocks)
- Dependencies pinned by `Cargo.toml` / `Cargo.lock`

Out of scope:

- Issues in upstream contextcrawler that aren't materially worsened by our
  downstream additions (please report those to rtk-ai/rtk).
- Issues in Tirith itself (report to sheeki03/tirith).
- Configuration mistakes a user makes in their own Claude Code /
  agent settings.
- DoS via running ContextCrawler with extremely large inputs locally —
  it's a single-user CLI.

---

## Trust boundary for command-string subcommands

`contextcrawler err`, `contextcrawler test`, and `contextcrawler summary`
accept a free-form command string (`trailing_var_arg`). By default this
string is **parsed as argv and executed without a shell**:

- Shell metacharacters (`|`, `;`, `&`, `<`, `>`, backtick, `$`, newline)
  cause the command to be rejected outright.
- The first token must not be:
  - a shell binary — `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`,
    `tcsh`, `csh`, `ash`, with their `.exe` Windows variants; `cmd`,
    `cmd.exe`, `powershell`, `powershell.exe`, `pwsh`, `pwsh.exe`; or
    multi-tool shells `busybox`, `toybox`;
  - an exec wrapper that replaces the process image with `arg[1+]` —
    `env`, `nice`, `nohup`, `time`, `timeout`, `gtimeout`, `ionice`,
    `chroot`, `setpriv`, `unshare`, `taskset`, `stdbuf`, `script`,
    `xargs`, `watch`, `sudo`, `doas`, plus the setuid launchers `su`,
    `runuser`, `pkexec`. Without this, an agent could bypass the
    shell guard via `env sh -c '<payload>'` or `sudo bash -c …`.

  Match is basename-only and case-insensitive (so `/usr/bin/bash` and
  `BASH.EXE` both trip). Tradeoff: a legitimate binary coincidentally
  named `sh` / `bash` / `env` / etc. cannot be invoked through these
  subcommands in argv mode. Use `--shell` if you have such a case;
  document it in your project's setup.

This guards against a prompt-injection → shell-injection chain where an
agent rewrites a user's `cargo test` into something like
`cargo test; <payload>`. In the default mode that string never reaches
`sh -c` and the agent gets a clear error instead of a silently widened
command.

Users who want pipes, redirects, or chained commands must pass
`--shell` explicitly. That opt-in restores the original `sh -c`
semantics and is the documented trust boundary: agent-rewritten input
should not carry `--shell`.

Tracked by [GHSA-3mmh-86cm-g6w4](https://github.com/thehoff/contextcrawler/security/advisories/GHSA-3mmh-86cm-g6w4).

---

## Terminal escape sequence stripping

`strip_ansi` in `src/core/utils.rs` removes the full set of terminal
escape sequences before output flows into LLM context:

- CSI (`ESC [ ... letter`) and DEC private modes (`ESC [ ? ... letter`)
- OSC (`ESC ] ... ST`) including window titles, palette changes,
  notifications
- OSC 8 hyperlinks — visible text is preserved, the URL payload is
  dropped (a hyperlink is a smuggling channel for instructions or
  exfil URLs)
- DCS, SOS, PM, APC (`ESC P|X|^|_ ... ESC \`)
- Standalone Fe/Fp/Fs escapes used by some pagers

Anything in those payloads counts as untrusted input and must not reach
the model. Coverage is tested against fixtures with mixed CSI/OSC/DCS
and explicit "OSC URL must not leak" assertions.

`strip_ansi` itself is correct; **callers must invoke it**. The Prisma
command paths in `src/cmds/js/prisma_cmd.rs` were missing the wrap on
their failure fallbacks (raw `eprint!` of stdout/stderr) and are now
fixed. A broader audit of remaining failure-path raw emits in
`cmds/git/`, `cmds/cloud/container.rs`, `cmds/dotnet/`, `cmds/python/`,
`cmds/js/pnpm_cmd.rs`, `cmds/system/grep_cmd.rs` is tracked as a
follow-up — those paths can still pass terminal escape sequences
through on tool failure.

Tracked by [GHSA-wjx4-ffxm-fxxp](https://github.com/thehoff/contextcrawler/security/advisories/GHSA-wjx4-ffxm-fxxp).

---

## Credential scrubbing in the tracking database

`contextcrawler` keeps a SQLite log of commands it has handled
(`tracking.db`, 90-day retention by default) so it can report token
savings via `gain --history`. Without scrubbing, that log would
preserve credentials passed on the command line and `gain --history`
would feed them back into agent context on every read.

`scrub_secrets` runs at the INSERT boundary in `src/core/tracking.rs`
and redacts:

- Credential-bearing flags: `--password`, `--token`, `--api-key`,
  `--secret`, `--access-key`, `--auth-token`, `--client-secret`
  (with either `=value` or space-separated value forms; underscore and
  hyphen variants both match; single- and double-quoted values with
  embedded spaces are also covered).
- `mysql -p<password>` (inline, no space) — only applied when the
  first token is `mysql`, `mysqldump`, `mysqladmin`, `mariadb`, or
  one of the mariadb-* variants (including `.exe` on Windows). Other
  tools that use `-p` for unrelated purposes (`curl -p3000`,
  `ssh -p2222`, `git log -p`) are not rewritten.
- HTTP `Authorization: Bearer|Basic|Token|ApiKey <value>` headers,
  including those passed via curl `-H`.
- URL-embedded credentials: `scheme://user:password@host`.
- AWS access key IDs (`AKIA…`, `ASIA…`).
- GitHub tokens: classic / OAuth / user-to-server / server / refresh
  PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) and fine-grained PATs
  (`github_pat_…`).
- Slack tokens (`xox[abprs]-…`).

False positives on benign command shapes were checked: plain `git
status`, `cargo test --lib`, `psql -h … -U …` and similar pass through
unchanged.

Known limitation: the scrubber operates on the post-`args.join(" ")`
string, which is lossy. A wrapper like `env mysql -p…` has `env` as
the first token and the mysql `-p` gating won't fire. A Windows path
with embedded spaces splits awkwardly before basename lookup. In both
cases the scrubber falls back to its non-mysql-scoped patterns, which
still catch flag-style secrets but miss the mysql `-p` shortcut. The
shell-exec-boundary branch refuses to spawn exec wrappers in the
err / test / summary subcommands, which limits exposure on that path.

Tracked by [GHSA-2cwv-rr7c-2p4c](https://github.com/thehoff/contextcrawler/security/advisories/GHSA-2cwv-rr7c-2p4c).

---

## TOML filter trust — global file gated

`~/.config/ctxcrl/filters.toml` (the user-global filter file) is now
SHA-256 pinned through the same trust store used for project-local
`.ctxcrl/filters.toml`. Previously the global file was loaded
unconditionally, which meant malware that could write to a user's
home directory could install a filter that silently rewrote any
command's output before the agent saw it — including hiding security
scanner findings via a `match_output` catch-all rule.

Default behaviour: an untrusted global filter file is **skipped, not
loaded**. To enable it:

```sh
contextcrawler trust --global    # review + SHA-256-pin the global file
contextcrawler untrust --global  # revoke trust
contextcrawler trust --list      # show all trusted filters (project + global)
```

Content changes auto-revoke trust. The CI env-var override
(`CTXCRL_TRUST_PROJECT_FILTERS=1` plus a known CI env var) applies to
both project and global files.

Surfaced during the 2026-05-15 audit's Codex re-review as H-3.

---

## Acknowledgements

We will credit security researchers in the published advisory and the
project changelog, with their permission.
