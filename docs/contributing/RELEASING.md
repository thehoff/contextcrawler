# Releasing ContextCrawler

End-to-end runbook for cutting a release of ContextCrawler. Follow this
in order. Steps that have automation are marked **[script]**; steps
that still require human judgement are marked **[review]**.

> **Prerequisite:** this runbook assumes `scripts/bump-version.sh` and
> `scripts/build-release.sh` are on the branch you're releasing from.
> The former ships on the `chore/release-runbook` branch in the v0.1.6
> cycle; the latter ships on `feat/sec-strip-build-paths`. Both land on
> `develop` when those branches merge — if you're cutting a release
> from before that merge, fall back to plain `cargo build --release`
> and skip the leak-verify steps below.

## Versioning

ContextCrawler ships under the `v0.1.x` line. The internal Rust crate
version (`Cargo.toml`) stays pinned to the **upstream rtk version**
this fork tracks (currently `0.39.0`); the ContextCrawler version
lives in `src/main.rs::CONTEXTCRAWLER_VERSION` and the README install
commands.

| Change type | Bump |
|---|---|
| Bugfix / security patch / doc-only | patch (`0.1.5 → 0.1.6`) |
| New capability behind an opt-in flag | patch |
| Breaking change in CLI surface or default behaviour | minor (`0.1.x → 0.2.0`) |
| Multi-month overhaul, contextcrawler/ctxcrl-tracking strategy change | minor or major after discussion |

We do not chase contextcrawler's own version numbers. When we rebase onto a new
upstream tag, that's reflected in `Cargo.toml`'s `version` field and in
the `(downstream of rtk X.Y.Z)` substring, but our own version line
increments per ContextCrawler-side change.

## Prerequisites

- Clean working tree on `develop` (or your release prep branch).
- `cargo`, `gh` CLI authenticated to `thehoff/contextcrawler`.
- All security-affecting branches merged. No open conflict markers in
  `SECURITY.md` (check with `git grep '<<<<<<<' SECURITY.md`).
- `cargo test` clean. `cargo deny check` clean (or the only ignored
  advisory is documented in `deny.toml` with reason).
- If this release closes a private GHSA: have the advisory IDs handy.

## 1. Bump version everywhere — **[script]**

```sh
scripts/bump-version.sh 0.1.5
```

This walks:

- `src/main.rs::CONTEXTCRAWLER_VERSION`
- `README.md` — `--tag v…` and `git checkout v…` lines

It does NOT touch `CHANGELOG.md` (intentional — see next step).

If you forget: `scripts/bump-version.sh` is idempotent. Run it again
with the right version; it diffs cleanly.

## 2. Update CHANGELOG — **[review]**

Prepend a new section above the current one. Format mirrors v0.1.5
(security-tagged subsections, GHSA links, test totals).

```markdown
## [0.1.6] — YYYY-MM-DD

One-paragraph framing of this release.

### Security
- **GHSA-…** — short title. One paragraph of what changed and why.

### Fixed (correctness)
- One bullet per non-security fix.

### Tests
- N passed, M failed (should be 0).
```

The CHANGELOG entry is the **canonical release narrative**. The
`gh release create` body is generated from it.

## 3. Verify build cleanliness — **[script]**

```sh
scripts/build-release.sh --verify
cargo test
cargo deny check
```

`--verify` rebuilds with `--remap-path-prefix` and asserts the binary
contains zero builder-path strings. If any of these fail, stop and fix
before tagging.

## 4. Commit + tag — **[script-assisted]**

```sh
git add Cargo.toml src/main.rs README.md CHANGELOG.md scripts/bump-version.sh
git commit -m "chore(release): v0.1.6

Brief one-line summary. Full notes in CHANGELOG.md."

git tag -a v0.1.6 -m "v0.1.6 — <one-line summary>"
```

If you're amending the v0.1.6 tag (because you spotted a missing
README bump etc. *minutes* after pushing):

```sh
git tag -d v0.1.6
git tag -a v0.1.6 -m "..."
git push contextcrawler v0.1.6 --force
```

**Do not** force-move a tag that's already been live for more than a
few minutes — anyone who downloaded it gets a different binary at the
same version string. Cut `v0.1.6.1` or `v0.1.7` instead.

## 5. Push to remote — **[script]**

```sh
git push contextcrawler develop v0.1.6
```

If you previously force-amended the v0.1.6 tag and the develop branch:
add `--force-with-lease` to develop. Use `--force` (not lease) only on
the tag.

## 6. Cut the GitHub release — **[review + gh]**

```sh
gh release create v0.1.6 \
    -R thehoff/contextcrawler \
    -t "v0.1.6 — <summary>" \
    --notes-file <(awk '/^## \[0\.1\.6\]/,/^## \[0\.1\.[0-9]*\] — /' CHANGELOG.md \
                  | sed '$d')
```

The `awk` extracts the v0.1.6 section from CHANGELOG.md, the trailing
`sed '$d'` drops the line that starts the next section. Verify the
release page reads cleanly before publishing.

## 7. Local install — **[script]**

```sh
scripts/build-release.sh --install
```

Copies the path-cleaned binary to `~/.local/bin/contextcrawler`. On
macOS the script re-applies an ad-hoc codesign on the destination —
without that step Apple Silicon's AMFI rejects the copied binary with
`load code signature error 2` and SIGKILLs it before `main()`. If you
see exit 137 on launch with an old fork of the script, that's the
cause; pull `develop` to get the fix.

Verify:

```sh
contextcrawler --version
which -a contextcrawler   # confirm both PATH entries (.local/bin and .cargo/bin) line up
```

If `~/.cargo/bin/contextcrawler` is still on an older version from a
prior `cargo install`, your terminal session may have it cached. New
shell or `hash -r`.

## 8. Publish GHSAs (if any) — **[review]**

For each draft advisory closed by this release:

1. Open the advisory on GitHub:
   `https://github.com/thehoff/contextcrawler/security/advisories/GHSA-…`
2. Fill in the patched version (`0.1.6`).
3. (Optional) Request a CVE.
4. Set a publication date, or publish immediately.

The CVE-request flow is GitHub's; they coordinate with MITRE. Allow a
few business days.

## 9. Sanity test the release — **[review]**

```sh
contextcrawler err echo hello                    # argv guard works on real path
contextcrawler err 'sh -c "echo bypass"'         # should refuse (shell-binary guard)
contextcrawler gain --history | head -5          # tracking.db readable, no secrets visible
```

## Failure modes

- **`commit.gpgsign` fails with "1Password agent returned an error"** —
  agent is locked. Either unlock 1Password and retry, or commit with
  `git -c commit.gpgsign=false commit …`. We default to signed commits
  for production release commits.
- **`gh release create` says "tag already exists"** — the tag was
  pushed but no release object exists. Add `--target HEAD` and the
  current ref; or run `gh release create v… --target $(git rev-parse v…)`.
- **`cargo install --git` users still see old version** — they have to
  re-run `cargo install --git … --tag vX.Y.Z` explicitly; cargo does
  not auto-update.

## Calendar

No fixed cadence. Cut a patch release when:

- A security fix lands (always).
- A correctness fix users have asked about lands.
- The accumulated changelog is "worth shipping" — judgement call.

Cut a minor release when:

- An opt-in default-off feature graduates to default-on.
- A CLI surface changes.

## Post-release housekeeping

- Update the local install at `~/.local/bin/contextcrawler` if you
  didn't via `--install`.
- Glance at GitHub Releases analytics 24h later — if downloads spike,
  something's interesting upstream.
- Skim `gh search issues "contextcrawler"` once a week or so to catch
  external reports that didn't go through Security Advisories.
