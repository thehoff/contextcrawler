# Tracking upstream rtk-ai/rtk

ContextCrawler is a downstream distribution of
[`rtk-ai/rtk`](https://github.com/rtk-ai/rtk). We rebase against
upstream periodically to inherit bugfixes, new command filters, and
security work — while keeping our own three differentiators:

1. The `contextzip-downstream` capability set (session JSONL compactor,
   multi-language stacktrace compressor, HTML web extractor, supply-
   chain pre-install gate).
2. The Tirith pre-execution gate integration.
3. ContextCrawler-specific security hardening that upstream has
   declined (the three v0.1.5 GHSAs and successors).

This doc is how we decide when to rebase, how to do it, and what to
skip.

## Repo layout

- `origin` → `https://github.com/rtk-ai/rtk` (upstream, read-only)
- `contextcrawler` → `git@github.com:thehoff/contextcrawler.git` (our
  fork, where releases live)

```sh
git remote -v
# contextcrawler  git@github.com:thehoff/contextcrawler.git (fetch)
# contextcrawler  git@github.com:thehoff/contextcrawler.git (push)
# origin          https://github.com/rtk-ai/rtk (fetch)
# origin          https://github.com/rtk-ai/rtk (push)
```

`develop` is our integration branch. Long-lived feature branches
(`feat-hook-engine`) get rebased into `develop` periodically.

## How to detect what's new upstream

```sh
git fetch origin
git fetch contextcrawler

# SHA delta (misleading — see caveat below):
git rev-list --left-right --count contextcrawler/develop...origin/develop

# Actual content delta — read the code:
git log contextcrawler/develop..origin/develop --oneline --no-merges
```

**Caveat: SHA-delta lies.** Our integration branches often merge in
upstream content under different SHAs, so a 900-commit delta does not
mean we're 900 commits of behaviour behind. Always verify by reading
the file at the call site before claiming a fix is missing.

This is the most important lesson from the 2026-05-15 audit — saved as
`feedback_verify_code_not_subjects.md` in project memory.

## What's worth taking

| Class | Default | Notes |
|---|---|---|
| Security fixes labelled `security:` or `fix(security):` | **Take** | Cross-check with `gh issue list --state all --search "security"` in upstream — closed-by-design issues are the real risk. |
| Permission / hook engine changes | **Take with review** | These touch our integrity model. Read the diff before merging. |
| New language-filter modules (cargo, go, python, …) | **Take** | Pure additions; low risk. |
| Refactors of `src/runner.rs` / `src/summary.rs` | **Take with review** | Re-verify our argv-mode guard still applies after the refactor. |
| Telemetry-related work | **Skip** | We disable telemetry downstream; upstream's salt-hash / opt-in flow doesn't apply. |
| Telemetry-related env vars and docs | **Skip** | Same. |
| Cosmetic / branding (contextcrawler → contextcrawler) | **Take** | Our rebrand sweep covers user-facing strings; upstream's own renames are typically not relevant. |
| Release-please / `chore(master): release …` commits | **Skip** | We have our own release flow. |
| TOML filter additions | **Take** | Inherits new built-in filters automatically. |

## What's worth not taking — upstream's "by design" calls

These upstream findings have been classified `wontfix` / `by design`
by rtk-ai but we have downstream patches for them:

| Upstream finding | Status upstream | Our patch |
|---|---|---|
| rtk-ai/rtk#640 C-1: `sh -c` shell-injection chain | "By design — Medium" | GHSA-3mmh-86cm-g6w4 (argv-mode guard) |
| rtk-ai/rtk#640 M-3: ANSI regex misses OSC/DCS | "Open — tracking" | GHSA-wjx4-ffxm-fxxp (extended `strip_ansi` + raw-emit sweep) |
| rtk-ai/rtk#640 M-2/M-5: secrets in tracking.db | "Acknowledged" | GHSA-2cwv-rr7c-2p4c (`scrub_secrets` at INSERT) |

When upstream eventually picks up these issues — and they may, the
narrative could shift — we re-evaluate whether to drop our downstream
patches and inherit instead.

## Rebase workflow

### Light-touch (every 1–2 weeks)

```sh
git fetch origin
git checkout develop
git rebase origin/develop
```

If the rebase succeeds without conflict in any of our hardened paths
(`src/cmds/rust/runner.rs`, `src/cmds/system/summary.rs`,
`src/core/utils.rs::strip_ansi`, `src/core/tracking.rs::scrub_secrets`,
`hooks/trust.rs`, `hooks/integrity.rs`), we're good.

Run tests + `scripts/build-release.sh --verify` before pushing.

### Heavy (every quarter or on demand)

When upstream has had a major rework (the kind that broke our pattern
matching), do a manual merge:

```sh
git checkout -b chore/rebase-onto-upstream-X.Y.Z develop
git merge origin/master  # or a specific upstream tag
# resolve conflicts; our security-hardened paths win by default
cargo test
scripts/build-release.sh --verify
```

For each conflict in a hardened path:

1. Read upstream's new version of the function.
2. Compare to ours — what did they change?
3. Apply their semantic change *on top of* our security guard. Our
   guard wins on disposition; their structural improvements are
   incorporated.
4. If the upstream refactor invalidates our guard (e.g. they moved
   `build_shell_command` out of `runner.rs`), reapply our guard at the
   new location.

After the merge: full Codex peer-review pass before tagging.

## What to do when upstream lands a fix for one of our GHSAs

If upstream rtk-ai eventually patches one of the issues we've already
fixed downstream, the rebase will produce a merge conflict in the
patched file (their fix vs ours). Decide:

- **If upstream's fix is stricter than ours**: take theirs, drop ours.
  Update the GHSA to "fixed upstream as of v0.1.x" and link the
  upstream commit. Re-evaluate residual risk in `THREAT_MODEL.md`.
- **If upstream's fix is weaker than ours**: keep ours. Note in the
  GHSA that upstream has a related but less complete patch. Stay
  downstream-only.
- **If they're equivalent**: take theirs to reduce diff. Same advisory
  housekeeping.

## Re-verification checklist after any rebase

| Check | Command |
|---|---|
| Tests | `cargo test` |
| Clippy | `cargo clippy --all-targets -- -D unsafe_code` |
| Audit | `cargo audit` |
| Deny | `cargo deny check` |
| Build leak | `scripts/build-release.sh --verify` (ships on `feat/sec-strip-build-paths` in the v0.1.6 cycle; fall back to a manual `cargo build --release && strings target/release/contextcrawler \| grep $HOME` if the script isn't on the branch yet) |
| Smoke (argv guard) | `contextcrawler err 'sh -c "x"'` should refuse |
| Smoke (OSC strip) | TBD: add a hyperlink emit fixture test |
| Smoke (scrub) | `contextcrawler proxy curl -H 'Authorization: Bearer x' …` then check `gain --history` for `<REDACTED>` |

If any smoke test fails, **don't ship**. Walk the diff against the
hardened paths to see what got moved.

## Cadence target

- Light rebase: aim for every other Friday or whenever upstream tags a
  new minor.
- Heavy rebase: once a quarter or in response to a security-relevant
  upstream change.

Drift hurts. The longer we wait, the more upstream's refactors break
our pattern-matching. The 913-commit gap we faced on 2026-05-15 was
recoverable but cost a full day of code reading — keep it tight.
