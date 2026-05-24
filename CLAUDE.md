<!-- rtk-instructions v3 -->
# ContextCrawler — Token-Optimized Commands

## Golden Rule

**Always prefix commands with `contextcrawler`**. If ContextCrawler has a dedicated filter, it uses it. If not, it passes through unchanged. This means ContextCrawler is always safe to use.

**Important**: Even in command chains with `&&`, use `contextcrawler`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
contextcrawler git add . && contextcrawler git commit -m "msg" && contextcrawler git push
```

## ContextCrawler Commands by Workflow

### Build & Compile (80-90% savings)
```bash
contextcrawler cargo build         # Cargo build output
contextcrawler cargo check         # Cargo check output
contextcrawler cargo clippy        # Clippy warnings grouped by file (80%)
contextcrawler tsc                 # TypeScript errors grouped by file/code (83%)
contextcrawler lint                # ESLint/Biome violations grouped (84%)
contextcrawler prettier --check    # Files needing format only (70%)
contextcrawler next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
contextcrawler cargo test          # Cargo test failures only (90%)
contextcrawler go test             # Go test failures only (90%)
contextcrawler jest                # Jest failures only (99.5%)
contextcrawler vitest              # Vitest failures only (99.5%)
contextcrawler playwright test     # Playwright failures only (94%)
contextcrawler pytest              # Python test failures only (90%)
contextcrawler rake test           # Ruby test failures only (90%)
contextcrawler rspec               # RSpec test failures only (60%)
contextcrawler test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
contextcrawler git status          # Compact status
contextcrawler git log             # Compact log (works with all git flags)
contextcrawler git diff            # Compact diff (80%)
contextcrawler git show            # Compact show (80%)
contextcrawler git add             # Ultra-compact confirmations (59%)
contextcrawler git commit          # Ultra-compact confirmations (59%)
contextcrawler git push            # Ultra-compact confirmations
contextcrawler git pull            # Ultra-compact confirmations
contextcrawler git branch          # Compact branch list
contextcrawler git fetch           # Compact fetch
contextcrawler git stash           # Compact stash
contextcrawler git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
contextcrawler gh pr view <num>    # Compact PR view (87%)
contextcrawler gh pr checks        # Compact PR checks (79%)
contextcrawler gh run list         # Compact workflow runs (82%)
contextcrawler gh issue list       # Compact issue list (80%)
contextcrawler gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
contextcrawler pnpm list           # Compact dependency tree (70%)
contextcrawler pnpm outdated       # Compact outdated packages (80%)
contextcrawler pnpm install        # Compact install output (90%)
contextcrawler npm run <script>    # Compact npm script output
contextcrawler npx <cmd>           # Compact npx command output
contextcrawler prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
contextcrawler ls <path>           # Tree format, compact (65%)
contextcrawler read <file>         # Full file content; --level minimal/aggressive to filter (opt-in)
contextcrawler grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
contextcrawler find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
contextcrawler err <cmd>           # Filter errors only from any command
contextcrawler log <file>          # Deduplicated logs with counts
contextcrawler json <file>         # JSON structure without values
contextcrawler deps                # Dependency overview
contextcrawler env                 # Environment variables compact
contextcrawler summary <cmd>       # Smart summary of command output
contextcrawler diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
contextcrawler docker ps           # Compact container list
contextcrawler docker images       # Compact image list
contextcrawler docker logs <c>     # Deduplicated logs
contextcrawler kubectl get         # Compact resource list
contextcrawler kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
contextcrawler curl <url>          # Compact HTTP responses (70%)
contextcrawler wget <url>          # Compact download output (65%)
contextcrawler web <url>           # Defuddle-extracted readable HTML
```

### Meta Commands
```bash
contextcrawler gain                # View token savings statistics
contextcrawler gain --history      # View command history with savings
contextcrawler gain --weak-filters # Rank tools by leaked tokens (where filters underperform)
contextcrawler gain --web          # Boot the local 127.0.0.1 dashboard (auto-shutdown after 1h idle)
contextcrawler gain --web --port N # ... pinned port
contextcrawler gain --web --no-browser  # ... SSH / headless mode
contextcrawler discover            # Analyze Claude Code sessions for missed opportunities
contextcrawler proxy <cmd>         # Run command without filtering (for debugging)
contextcrawler init                # Add ContextCrawler instructions to CLAUDE.md
contextcrawler init --global       # Add ContextCrawler to ~/.claude/CLAUDE.md
contextcrawler trust               # Trust project-local TOML filters
contextcrawler trust --global      # Trust user-global TOML filters
```

### Local dashboard (`gain --web`)

Read-only HTTP surface on `127.0.0.1`. Eight panes: Summary, By day,
Weak filters, Parse failures, Release boundaries, Security (Tirith
downgrades + supply-chain verdicts), Installs (per-project ledger),
Insights (stub). See [`docs/FEATURE_MAP.md`](docs/FEATURE_MAP.md) for
the full pane-and-endpoint inventory.

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget, web | 65-70% |

Overall average: **60-90% token reduction** on common development operations.

## Feature inventory

See [`docs/FEATURE_MAP.md`](docs/FEATURE_MAP.md) for the single-page
matrix of every shipped / planned / stubbed capability with issue links
and status flags.
<!-- /rtk-instructions -->
