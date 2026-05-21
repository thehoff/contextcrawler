# Contributing to ContextCrawler

**Welcome!** We appreciate your interest in contributing to ContextCrawler.

ContextCrawler is a coding agent proxy that cuts noise from command outputs.
It filters and compresses CLI output before it reaches your LLM context,
saving 60-90% of tokens on common operations. The vision is to make
AI-assisted development faster and cheaper by eliminating unnecessary token
consumption.

## Design Philosophy

Four principles guide every design decision. Understanding them helps you
write contributions that fit naturally into the project.

### Correctness vs Token Savings

When a user or LLM explicitly requests detailed output via flags, respect
that intent. Compressing explicitly-requested detail defeats the purpose —
the LLM asked for it because it needs it.

Filters should be flag-aware: default output gets aggressively compressed,
but verbose and detailed flags should pass through more content. When in
doubt, preserve correctness.

For example, `contextcrawler cargo test` shows failures only, achieving
roughly 90% savings. But `contextcrawler cargo test -- --nocapture` preserves
all output because the user explicitly asked for it.

### Transparency

The LLM doesn't know ContextCrawler is involved for most commands, because
hooks rewrite commands silently. ContextCrawler's output must be a valid,
useful subset of the original tool's output, not a different format the LLM
wouldn't expect. If an LLM parses `git diff` output, the filtered version
must still look like `git diff` output.

Don't invent new output formats. Don't add tool-specific headers or markers
in the default output. The filtered output should be indistinguishable from
a shorter version of the real command's output.

### Never Block

If a filter fails, fall back to raw output. The tool should never prevent a
command from executing or producing output. Better to pass through unfiltered
than to error out. The same applies to hooks: exit 0 on all error paths so
the agent's command runs unmodified.

Every filter needs a fallback path. Every hook must handle malformed input
gracefully.

### Zero Overhead

Startup time must stay under 10 milliseconds. There is no async runtime and
no config file I/O on the critical path. If developers perceive any delay,
they will disable the proxy. Speed is the difference between adoption and
abandonment.

Always use `lazy_static!` for regex compilation. No network calls are made
at runtime. No disk reads happen in the hot path. Benchmark before and after
any change with `hyperfine`.

## Commit Messages

ContextCrawler uses Conventional Commits and release-please to auto-generate
the changelog, version bumps, and GitHub releases. Never edit `CHANGELOG.md`
manually — it is fully managed by release-please from your commit messages.

The commit format is `<type>(<scope>): <short description>`. For example:

```
feat(kubectl): add pod log filtering
fix(git): preserve merge commit messages in log filter
perf(cargo): lazy-compile clippy regex patterns
feat!(hook): change rewrite config format
```

These commit messages become changelog entries directly when release-please
creates a release PR. Write them as if users will read them.

## Pull Request Process

Each PR must focus on a single feature, fix, or change. The diff must stay
in-scope with the description written in the PR title and body. Out-of-scope
changes — unrelated refactors, drive-by fixes, formatting of untouched files
— must go in a separate PR.

For large features or refactors, prefer multi-part PRs over one enormous PR.
Split the work into logical, reviewable chunks that can each be merged
independently.

Small, focused PRs are easier to review, safer to merge, and faster to ship.
Large PRs slow down review, hide bugs, and increase merge conflict risk.

Once merged, changes are tested on the `develop` branch alongside other
features. When a maintainer is satisfied with the state of `develop`, they
release to `master` under a specific version.
