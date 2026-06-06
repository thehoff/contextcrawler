---
title: Token Savings Analytics
description: Measure and analyze your contextcrawler token savings with contextcrawler gain
sidebar:
  order: 1
---

# Token Savings Analytics

`contextcrawler gain` shows how many tokens contextcrawler has saved across all your commands, with daily, weekly, and monthly breakdowns.

## Quick reference

```bash
# Default summary
contextcrawler gain

# Temporal breakdowns
contextcrawler gain --daily          # all days since tracking started
contextcrawler gain --weekly         # aggregated by week
contextcrawler gain --monthly        # aggregated by month
contextcrawler gain --all            # all breakdowns at once

# Classic flags
contextcrawler gain --graph          # ASCII graph, last 30 days
contextcrawler gain --history        # last 10 commands
contextcrawler gain --quota          # monthly quota savings estimate (default tier: 20x)
contextcrawler gain --quota -t pro   # use pro tier token budget for estimate

# Export
contextcrawler gain --all --format json > savings.json
contextcrawler gain --all --format csv  > savings.csv
```

## Daily breakdown

```bash
contextcrawler gain --daily
```

```
📅 Daily Breakdown (3 days)
════════════════════════════════════════════════════════════════
Date            Cmds      Input     Output      Saved   Save%
────────────────────────────────────────────────────────────────
2026-01-28        89     380.9K      26.7K     355.8K   93.4%
2026-01-29       102     894.5K      32.4K     863.7K   96.6%
2026-01-30         5        749         55        694   92.7%
────────────────────────────────────────────────────────────────
TOTAL            196       1.3M      59.2K       1.2M   95.6%
```

- **Cmds**: contextcrawler commands executed
- **Input**: Estimated tokens from raw command output
- **Output**: Actual tokens after filtering
- **Saved**: Input - Output (tokens that never reached the LLM)
- **Save%**: Saved / Input × 100

## Weekly and monthly breakdowns

```bash
contextcrawler gain --weekly
contextcrawler gain --monthly
```

Same columns as daily, aggregated by Sunday-Saturday week or calendar month.

## Export formats

| Format | Flag | Use case |
|--------|------|----------|
| `text` | default | Terminal display |
| `json` | `--format json` | Programmatic analysis, dashboards |
| `csv` | `--format csv` | Excel, Python/R, Google Sheets |

**JSON structure:**
```json
{
  "summary": {
    "total_commands": 196,
    "total_input": 1276098,
    "total_output": 59244,
    "total_saved": 1220217,
    "avg_savings_pct": 95.62
  },
  "daily": [...],
  "weekly": [...],
  "monthly": [...]
}
```

## Typical savings by command

| Command | Typical savings | Mechanism |
|---------|----------------|-----------|
| `git status` | 77-93% | Compact stat format |
| `eslint` | 84% | Group by rule |
| `jest` | 94-99% | Show failures only |
| `vitest` | 94-99% | Show failures only |
| `find` | 75% | Tree format |
| `pnpm list` | 70-90% | Compact dependencies |
| `grep` | 70% | Truncate + group |

## How token estimation works

contextcrawler estimates tokens using `text.len() / 4` (4 characters per token average). This is accurate to ±10% compared to actual LLM tokenization — sufficient for trend analysis.

```
Input Tokens  = estimate_tokens(raw_command_output)
Output Tokens = estimate_tokens(rtk_filtered_output)
Saved Tokens  = Input - Output
Savings %     = (Saved / Input) × 100
```

## Database

Savings data is stored locally in SQLite:

- **Location**: `~/.local/share/ctxcrl/history.db` (Linux / macOS)
- **Retention**: 90 days (automatic cleanup)
- **Scope**: Global across all projects and Claude sessions

```bash
# Inspect raw data
sqlite3 ~/.local/share/ctxcrl/history.db \
  "SELECT timestamp, rtk_cmd, saved_tokens FROM commands
   ORDER BY timestamp DESC LIMIT 10"

# Backup
cp ~/.local/share/ctxcrl/history.db ~/backups/ctxcrl-history-$(date +%Y%m%d).db

# Reset
rm ~/.local/share/ctxcrl/history.db    # recreated on next command
```

## Analysis workflows

```bash
# Weekly progress: generate a CSV report every Monday
contextcrawler gain --weekly --format csv > reports/week-$(date +%Y-%W).csv

# Monthly budget review
contextcrawler gain --monthly --format json | jq '.monthly[] |
  {month, saved_tokens, quota_pct: (.saved_tokens / 6000000 * 100)}'

# Cron: daily JSON snapshot for a dashboard
0 0 * * * contextcrawler gain --all --format json > /var/www/dashboard/ctxcrl-stats.json
```

**Python/pandas:**
```python
import pandas as pd
import subprocess

result = subprocess.run(['contextcrawler', 'gain', '--all', '--format', 'csv'],
                       capture_output=True, text=True)
lines = result.stdout.split('\n')
daily_start = lines.index('# Daily Data') + 2
daily_end = lines.index('', daily_start)
daily_df = pd.read_csv(pd.StringIO('\n'.join(lines[daily_start:daily_end])))
daily_df['date'] = pd.to_datetime(daily_df['date'])
daily_df.plot(x='date', y='savings_pct', kind='line')
```

**GitHub Actions (weekly stats):**
```yaml
on:
  schedule:
    - cron: '0 0 * * 1'
jobs:
  stats:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo install contextcrawler
      - run: contextcrawler gain --weekly --format json > stats/week-$(date +%Y-%W).json
      - run: git add stats/ && git commit -m "Weekly contextcrawler stats" && git push
```

## Quota estimate

`--quota` estimates how many tokens contextcrawler has saved relative to your monthly subscription budget, so you can see the cost impact of those savings.

```bash
contextcrawler gain --quota          # uses 20x tier by default
contextcrawler gain --quota -t pro   # Claude Pro plan budget
contextcrawler gain --quota -t 5x    # 5× usage plan budget
contextcrawler gain --quota -t 20x   # 20× usage plan budget
```

The tiers (`pro`, `5x`, `20x`) correspond to Anthropic Claude API subscription levels, each with a different monthly token allocation. contextcrawler uses those allocations as a denominator to express your savings as a percentage of your budget.

:::tip[Find missed savings]
`contextcrawler gain` shows what contextcrawler saved. To find commands that ran *without* contextcrawler and calculate what you lost, see [contextcrawler discover](./discover.md).
:::

## Troubleshooting

**No data showing:**
```bash
ls -lh ~/.local/share/ctxcrl/history.db
sqlite3 ~/.local/share/ctxcrl/history.db "SELECT COUNT(*) FROM commands"
git status    # run any tracked command to generate data
```

**Incorrect statistics:** Token estimation is a heuristic. For precise counts, use `tiktoken`:
```bash
pip install tiktoken
git status > output.txt
python -c "
import tiktoken
enc = tiktoken.get_encoding('cl100k_base')
print(len(enc.encode(open('output.txt').read())), 'actual tokens')
"
```
