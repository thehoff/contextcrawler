# Module audit — `src/hooks/supply_chain_gate.rs`

Internal code review. 1010 lines. Module-level security audit performed
during the 2026-05-15 overnight maintenance session.

## What it does

Detects `npm` / `pnpm` / `yarn` / `pip` / `uv` / `poetry` / `pipx`
install commands inside a shell command string, queries the relevant
registry (npm or PyPI) for publish time, and OSV.dev for known
vulnerabilities. Returns a `Verdict` (`Skip` / `Allow` / `Block(...)`
/ `Unavailable(...)`) that the auto-allow hook path uses to downgrade
the verdict when packages fail an age cooldown or carry a HIGH+ CVE.

Trust placement: this module sits inside the
`PermissionVerdict::Allow` codepath only. Documented in commit
`f3bdc35` (gate-design comment). Anything not auto-allowed by contextcrawler's
permission engine never reaches this code.

## Verdict surface

| Variant | When | Downstream effect |
|---|---|---|
| `Skip` | Gate disabled in config, env override, or no install detected | Caller continues normally |
| `Allow` | Every package passes age + CVE checks | Caller continues with the original Allow |
| `Block(findings)` | One or more packages fail | Caller downgrades Allow → Ask |
| `Unavailable(err)` | Network failure on any package query | Caller's fail-open default keeps Allow; logged |

## Good practices observed (no change needed)

- **HTTP timeouts** (`8s`) set on every GET and POST. `core/runner.rs`
  level retries are not used here — that's intentional, fail-open is
  faster than retrying.
- **Body size cap** at 64 MB (`HTTP_MAX_BYTES`). Large enough for
  npm's `@types/node` full doc (~30 MB) but bounded so a hostile
  registry can't OOM us. `ureq::into_string()`'s 10 MB default would
  fail on legitimate packages — the explicit `take().read_to_end()`
  is the right call.
- **User-Agent** set so we're identifiable in registry logs.
- **Percent-encoding** for URL path segments (`urlencoding` helper at
  line 504). Allows `@` and `/` unencoded — correct for npm scoped
  package paths.
- **Cache filename hardening** at `cache_file` (line 584): rejects
  empty names, `..` traversal, backslashes, control chars, `:`, `*`,
  `?`. Maps `/` → `_` and `@` → `_at_` for filesystem safety.
- **Path-traversal guard** before writing the cache file is comprehensive.
- **Cache TTL** of 24h via `fetched_at` field. Stale entries are
  refetched, not returned.
- **Cache key includes pinned version** (`pkg@<ver>` or
  `pkg@__latest__`). Two pins of the same package don't collide.
- **HTTPS by default** via `ureq`; no insecure-fallback path.
- **Severity parser** in `osv_severity` defaults to `High` for unknown
  data, biasing toward blocking. Good fail-safe direction.
- **Negative-age clamp** at line 725: `(Utc::now() - publish).max(0)`.
  Defends against a publisher with skewed clock or a future-dated
  release; a malicious-publisher attack that backdates wouldn't help
  them (we want to block recent releases, not future-dated ones).
- **Dedupe within an install** (line 685): `pip install foo bar foo`
  only queries `foo` once.
- **Editable / path / URL token detection** (`install.has_editable`).
  Surfaces `pip install -e .` as a finding when `allow_editable` is
  off; falls through and still vets sibling named packages.

## Findings

### F-01: Cache filename collision (low / theoretical)

**Location:** `cache_file` at line 599.

```rust
let safe = pkg.replace('/', "_").replace('@', "_at_");
```

`@scope/foo` becomes `_at_scope_foo`. A package literally named
`_at_scope_foo` would produce the same cache filename. Both names are
valid npm identifiers (npm restricts only the first character not to
be `.` / `_` — actually it forbids leading `_` for new packages, but
legacy `_`-prefixed packages exist; `_at_scope_foo` would be rejected
by current npm but is reachable via direct registry URLs).

**Attack chain:**
1. Attacker publishes `_at_scope_foo` (or finds an existing legacy
   name with the right shape).
2. Attacker waits for someone to install `@scope/foo`, populating the
   cache.
3. Attacker convinces the user to `npm install _at_scope_foo` — the
   gate reads the cached metadata which actually describes
   `@scope/foo`. If `@scope/foo` is well-aged and CVE-free, the
   attacker's `_at_scope_foo` (which might be a fresh malicious
   package) gets falsely cleared.

**Impact:** Bypass of the age cooldown for one package only, requires
the attacker to pick a colliding name AND get the user to install the
victim package first. Mitigated by the 24h cache TTL.

**Recommendation:** Switch to a separator that can't appear in npm
package names. `~` is forbidden in npm names; `cache_file` could use
that:

```rust
let safe = pkg.replace('/', "~slash~").replace('@', "~at~");
```

Or hash the package name with sha256 (8-byte prefix) and store the
mapping in a sidecar. Cheaper: just use `%2F` and `%40` (the
percent-encoded forms).

### F-02: Serial per-package latency (informational)

**Location:** `check()` loop at line 686.

Each package query is serial: `npm_metadata()` → `osv_query()` → next
package. With 8s timeouts and three packages in `npm install a b c`,
worst case is 6 round-trips × 8s = **48s of latency** before the gate
returns. In practice, registry p50 is ~350ms and OSV is ~565ms, so a
typical install is ~3s per package = 9s for three packages. Cache hits
are sub-ms.

The audit report (`notes/research/supply-chain-audit-report.md`)
mentions "Parallel mode: ~600 ms p50" — that benchmark uses parallel
in-flight requests, not the production implementation. Worth noting
the discrepancy or implementing parallelism for `Iterator<install>`.

**Recommendation:** Optional. If user-perceptible latency complaints
come in, parallelize the per-package fetches via `std::thread::spawn`
(no async runtime dependency). The pattern is well-bounded — N
packages per command, N typically ≤ 5.

### F-03: OSV severity score parsing is substring-based (low)

**Location:** `osv_severity()` at line 549.

```rust
if score.contains("CRITICAL") { ... }
else if score.contains("HIGH") { ... }
```

`score` is OSV's free-form string — sometimes a CVSS vector like
`CVSS:3.0/...`, sometimes a literal `HIGH`. Substring match works
today but is fragile to OSV changing its data shape (e.g. inverted
case, or `CRITICAL_REMOTE_CODE_EXECUTION` matching `CRITICAL` when
the user actually wants only true `CRITICAL`).

Also: the loop returns on the *first* matching entry, not the
maximum. If OSV returns multiple severity entries (different scoring
systems), only the first is considered.

**Recommendation:** Parse CVSS score numerically when the string
starts with `CVSS:`. Score ≥ 9.0 → Critical, 7.0–8.9 → High, etc.
Keep the substring fallback for non-CVSS strings. Default-to-High
behaviour stays as a fail-safe.

### F-04: `Unavailable` collapses multiple errors into the first

**Location:** `check()` line 717.

```rust
Err(e) => {
    transient_err.get_or_insert(e);
    continue;
}
```

Only the first transient error is reported. If five packages all fail
the registry query for different reasons, the user sees one of them.
Diagnostic minor; doesn't affect security.

**Recommendation:** Collect errors into a vec and report all. Or
just count: `Verdict::Unavailable(format!("{}/{} packages failed",
n_failed, n_total))`.

### F-05: Cache poisoning via local file write race (low)

**Location:** `cache_put()` at line 622.

```rust
if let Ok(json) = serde_json::to_string(&entry) {
    let _ = fs::write(&path, json);
}
```

`fs::write` truncates and overwrites without atomic temp-file rename.
Two concurrent contextcrawler runs writing the same cache file could
interleave. The cache content is small (~200 bytes), so the kernel
will usually atomic-write at that size, but it's not guaranteed.

**Recommendation:** Use `tempfile::persist` for atomic write. Already
have `tempfile` in deps.

```rust
let tmp = tempfile::NamedTempFile::new_in(parent)?;
fs::write(tmp.path(), json)?;
tmp.persist(&path)?;
```

### F-06: No content-type validation on registry response (low)

**Location:** `http_get_json()` at line 394.

`serde_json::from_slice(&buf)` is called on whatever the server
returned. A registry compromise that serves HTML or a binary blob
would just produce a parse error and surface as `Unavailable`. Real
risk is low (registries are trusted endpoints), but a Content-Type
check would be cheap defense in depth.

## Test coverage

| Surface | Coverage |
|---|---|
| `detect_installs` | Exists, multiple ecosystems tested |
| `parse_package_args` | Exists; covers `-e .`, `git+`, `pkg==X.Y.Z` |
| `split_name_version` | Exists |
| Cache TTL behaviour | Not seen — worth adding |
| Cache filename collision | Not seen — F-01 needs a test |
| Negative age clamp | Not seen — `Utc::now() - future_date` |
| OSV severity parsing edge cases | Not seen |
| HTTP timeout / size cap | Not seen |
| `Verdict::Unavailable` propagation | Not seen |

**Recommendation:** Add the missing test surface in a follow-up
branch. Highest priority: the cache collision tests (closes F-01)
and the OSV severity parser (catches F-03 regression).

## Summary

The module is well-engineered for the security-sensitive role it
plays. Six observations are listed above. None are blocking; F-01
(cache collision) and F-03 (severity parser fragility) are worth
addressing in the next sweep. F-05 (atomic cache write) and F-06
(content-type check) are pure hardening. F-02 (serial latency) and
F-04 (first-error reporting) are UX, not security.

No High or Critical findings. No active or near-term attack vector.
