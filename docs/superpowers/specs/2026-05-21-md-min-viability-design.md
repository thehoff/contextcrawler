# md-min — Markdown Minification Viability Design

**Date:** 2026-05-21
**Status:** Approved design (v2 — post Codex + Gemini peer review) — pending implementation plan
**Branch:** `feat/md-min-viability`

## Problem

Large markdown documents fed to an LLM carry token overhead that does not
help the model comprehend the document: redundant whitespace (an estimated
20%+ of a typical doc) and markdown markup the model arguably does not need
(emphasis markers, heading hash characters, link syntax).

The goal is to **losslessly compress markdown documents** — shrink token
cost with **zero impact on inference quality**. "Lossless" here means
*information-* and *comprehension-*lossless, not byte-identical: the model
must still answer questions about the document exactly as well as it does
from the raw form.

Whether stripping a given class of markup is genuinely zero-loss is an
**empirical question**, not a matter of assertion. This design therefore
specifies a *measurement harness* first. Wiring anything into the
command-rewrite path is deliberately deferred to a later, separate spec,
gated on the benchmark verdict.

### Out of scope

- TOON / structured-data encodings — wrong tool for prose, rejected.
- In-path automatic rewriting of `read`/`cat` on `.md` files — deferred to
  a future spec, contingent on this benchmark's result.
- Lossy summarisation. The feature is lossless compression only.

## Approach

Build a real Rust markdown minifier (`md-min`) with additive strip tiers,
plus a council-driven viability harness that measures, per tier, token
savings against inference-quality delta across Claude, Codex, and Gemini.
The stripper is production-grade code from day one, so the harness measures
the path that would actually ship — a future in-path rollout is then just
wiring plus a flag, not a re-implementation.

## Peer-review provenance (v2)

v1 of this spec was reviewed by Codex and Gemini. They converged on three
critical flaws and several important ones. v2 incorporates every finding:

- **Corpus contamination** — a Wikipedia corpus would be answered from the
  models' parametric memory, not the supplied document; destructive tiers
  would falsely pass. v2 corpus is private/synthetic docs only.
- **Statistical invalidity** — v1's sample and threshold were noise-level.
  v2 specifies sample size, a paired non-inferiority test, and a
  multiple-comparisons correction.
- **Tier 3 / L2 contradiction** — v1 stripped link URLs while declaring
  URLs preserved content. v2 keeps URLs always; tier 3 strips only link
  *markup*.
- Plus: tier 0 redefined as post-parser; L1 as allowed-mutation
  comparison; L5 replaced (stochastic summarisation → deterministic
  extraction); a negative-control doc added; long-range attention probes
  added; token-array profiling for tier 1; latency benchmark added.

## Components

### 1. `md-min` — Rust markdown minifier

- **Location:** `src/cmds/system/md_min.rs`.
- **Invocation:** explicit subcommand `contextcrawler md-min <file> --tier <0-4>`.
  Explicit only — **not** wired into the `read`/`cat` auto-rewrite path.
- **Implementation:** parses with `pulldown-cmark` (CommonMark, synchronous,
  no async — adds `pulldown-cmark` + `pulldown-cmark-to-cmark`) into an
  event stream; drops or rewrites events per tier; re-serialises to
  markdown. A real parser, not regex.
- **Fallback:** per RTK convention, parse failure emits the original input
  unchanged; the command never blocks the user.
- **Latency:** `md-min` records its own parse+strip+serialise wall time;
  the harness aggregates it. The eventual in-path decision must weigh CPU
  cost against tokens saved — a parser that costs more time than the saved
  tokens save is a net loss and the feature is abandoned.

### 2. Strip tiers

Tiers are **additive** — tier N applies everything tier N-1 does, plus
more. They locate the *cliff edge*: the highest tier still rated lossless.

**Tier 0 is defined as the post-parser re-serialised output**, not the raw
input bytes. `pulldown-cmark` round-tripping normalises markdown
(list markers, reference links, incidental whitespace). Every tier — and
every validation layer — compares against this post-parser tier 0, so the
serialiser's own normalisation is never mistaken for stripping loss.

| Tier | Strips (relative to tier 0) | Claim |
|---|---|---|
| **0** | nothing — post-parser re-serialisation only | control / baseline |
| **1** | 3+ blank lines collapse to 1; trailing-space hard breaks normalised (form chosen by token-array profiling — see below); table cell padding; HTML comments; list-marker spacing | render-identical, provably lossless |
| **2** | + bold / italic / strikethrough markers (text kept); horizontal rules | decoration only — text content identical |
| **3** | + heading `#` characters; blockquote `>` markers; link **markup** only — `[text](url)` becomes `text url`, the **URL is always kept** | the contested hypothesis |
| **4** | + list markers; code-fence language tags | structure-flattened — expected to lose; the cliff control |

**Tier 1 hard-break profiling.** v1 assumed `  \n` → `\\\n` saves tokens.
Codex/Gemini noted byte-pair encoders may tokenise `  \n` as a single
token and fragment `\\\n` into several — the "compression" could *raise*
token count. Cycle 1 therefore profiles the actual `tiktoken` token arrays
for each candidate hard-break form and picks the form that genuinely
reduces tokens, or leaves trailing spaces untouched if none does.

**Link handling (tier 3).** URLs are payload, especially in technical
docs — they are never stripped. Tier 3 removes only the bracket/paren
*markup*, leaving link text and URL as adjacent plain text. This keeps
tier 3 consistent with L2 (URLs are preserved content).

### 3. Viability harness

- **Location:** `harness/md-viability/` — research harness, not production.
- **Orchestrator:** Python.

**Pipeline:**

1. **Corpus** — `harness/md-viability/corpus/`: documents the council has
   **not** memorised, so retrieval QA measures reading, not parametric
   recall. Two families:
   - *Private/real technical docs* — unreleased or local project docs,
     READMEs, `docs/` trees. This is the production use case and the
     primary evaluation set; the verdict is driven by it.
   - *Synthetic docs* — generated with controllable structure (heading
     depth, list nesting, table density, prose ratio) and **fictional
     facts**, so answers cannot come from training data. Used for
     structural stress coverage.
   Plus **one negative-control document** — a doc deliberately corrupted
   (facts deleted and scrambled relative to its QA ground truth). The
   harness MUST flag it as lossy. If it does not, the harness itself is
   broken and no verdict is trusted. This is the harness self-test.
   An HTML rung is generated deterministically by rendering each markdown
   doc to HTML (`pulldown-cmark` HTML output) — a synthetic baseline
   ceiling, no external source needed.
2. **QA generation** — one model generates, per document, from the raw
   (post-parser tier-0) document:
   - *Retrieval QA* (L3) — semantic questions. The generation prompt
     **forbids structural references** ("in the second list", "under the
     Architecture heading") so a question is never unanswerable purely
     because a later tier removed the structure it named.
   - *Adversarial structure probes* (L4) — questions targeting section
     hierarchy, list order / membership / count, emphasis-carried meaning,
     and **long-range synthesis** (facts that must be aggregated from the
     beginning, middle, and end of the document — the "lost in the middle"
     attention stress).
   Target volume: **≥1,000 graded questions per tier per model** (across
   all docs) so a 1–2% effect is distinguishable from run-to-run jitter.
   Both sets are frozen to `qa/<doc>.json`, committed, **identical across
   all tiers and formats**, and human-reviewable.
3. **Strip** — `contextcrawler md-min` over each document at each tier.
4. **Council inference** — every (document, format, question) triple is
   sent to `claude`, `codex`, `gemini`. Format ladder: rendered HTML →
   markdown tier 0 → tiers 1–4. Each (prompt, model, model-version)
   response is **cached**; reruns reuse the cache, so cost is paid once
   and infrastructure failures are separable from benchmark variance.
   Model identifiers and versions are recorded in the report.
5. **Scoring** — an LLM-as-judge grades each answer against ground truth.
   The judge prompt evaluates **semantic truth only** — it explicitly
   ignores formatting, phrasing, and markdown adherence, to neutralise
   judge format/length bias.
6. **Token metric** — `tiktoken o200k_base` as the stable cross-model
   proxy; savings *ratios* are the figure of merit.

### 4. Validation layer

Losslessness is established by **independent checks**, not one metric. The
two deterministic layers run first and cost nothing — they catch gross
stripper bugs before any council call. The behavioural layers attack
comprehension loss from independent angles.

| Layer | Method | Catches |
|---|---|---|
| **L1 — AST allowed-mutation equivalence** | Parse raw and stripped to the `pulldown-cmark` event stream. Each tier *declares* the event deletions it is permitted. L1 asserts: stripped AST == tier-0 AST minus exactly the declared deletions — nothing else changed. Not a strict byte diff (which tier 0 itself would fail); an allowed-mutation comparison. | Stripper bugs — undeclared structure loss |
| **L2 — Flattened-text equivalence** | Flatten *both* raw and stripped to plain text (all markup removed from both), normalise whitespace, assert equality. Robust to word-boundary shifts that a token-extraction check would false-flag. | Any body-text / number / identifier loss |
| **L3 — Retrieval QA accuracy** | Council answers semantic retrieval QA; accuracy delta versus tier 0. | General comprehension loss |
| **L4 — Adversarial + long-range probes** | Council answers structure-targeted and long-range-synthesis QA. | Subtle structural and attention-degradation loss |
| **L5 — Deterministic fact extraction** | Council emits a JSON list of every atomic fact of declared types (numbers, dates, identifiers, URLs, named entities) from raw vs stripped; compare the sets. Replaces v1's stochastic free-recall summarisation, which would false-fail on summariser sampling variance. | Information loss never probed by QA |
| **L6 — Cross-model agreement (diagnostic)** | Inter-model answer agreement, raw vs stripped, derived from L3/L4. A *diagnostic signal*, not an independent pass/fail gate (it shares data with L3/L4). | Ambiguity introduced by stripping |

**Verdict rule.** A tier passes only if:
- **L1 and L2 are clean** (hard, deterministic), and
- **L3, L4, L5** show **non-inferiority** versus tier 0 under a paired
  permutation test (per model), at a pre-registered margin, with a
  **Holm–Bonferroni correction** applied across the family of tier ×
  model × layer comparisons, and
- **L6** raises no agreement-collapse flag.

Per-cell accuracy is reported with confidence intervals. The non-inferiority
margin and alpha are **pre-registered in the spec before the run** (set in
the implementation plan) so the verdict is not fitted to the data. The
negative-control document must be flagged lossy by L3/L4/L5 — a run where
it is not is void.

### 5. Report

- **Location:** `harness/md-viability/reports/md-viability-YYYY-MM-DD.md`.
- **Contents:** per format-ladder rung — token savings, per-model accuracy
  with confidence intervals, accuracy delta versus tier 0, the non-inferiority
  test result; the negative-control result; `md-min` latency; the computed
  verdict; model identifiers/versions; and a recommendation on what, if
  anything, should be wired into the rewrite path.
- First-class research deliverable — the artifact that gates the future
  in-path spec.

## Data flow

```
private/real docs ─┐
synthetic docs ────┼─> corpus/*.md  ──> render ──> corpus/*.html
negative control ──┘        │
                            ├──> QA generation (semantic + adversarial +
                            │     long-range; one model, tier-0 doc)
                            │         └──> qa/*.json  (frozen, committed)
                            │
                            └──> md-min --tier 0..4 ──> stripped variants ──┐
                                              + rendered HTML ──────────────┤
qa/*.json ──────────────────────────────────────────────────────────────────┤
                                                                             ▼
                                       council inference (claude, codex, gemini)
                                                  [response cache]
                                                                             │
                                                                             ▼
                                  L1/L2 deterministic  +  L3/L4/L5 judged
                                  +  L6 agreement  +  tiktoken  +  latency
                                                                             │
                                                                             ▼
                                  paired non-inferiority test + Holm–Bonferroni
                                                                             │
                                                                             ▼
                                reports/md-viability-YYYY-MM-DD.md  (verdict)
```

## Error handling

- **Stripper:** parse failure emits the original input unchanged (RTK
  fallback convention); a malformed tier argument is a hard usage error.
- **Harness:** a failed council call is retried with backoff, then recorded
  as a missing data point (not an aborted run); the report states per-cell
  completeness. Cached responses make infrastructure failure separable from
  benchmark variance.
- **Judge:** an unparseable verdict is retried once, then recorded ungraded
  and excluded from the denominator, with the exclusion count reported.
- **Run budget:** the harness enforces a hard ceiling on uncached council
  calls per run and supports a `smoke` subset (few docs) versus a `full`
  run, so iteration is cheap.

## Testing

- **Stripper:** snapshot tests (`insta`) per tier on real fixtures;
  token-savings assertions. Validation layers **L1** and **L2** are
  deterministic Rust tests over the corpus, running in `cargo test`,
  per tier.
- **Harness:** QA JSON schema validation; corpus re-fetch/re-generation is
  byte-stable; a single-document `smoke` run confirming all three CLIs and
  the judge respond; the negative-control self-test (harness must flag the
  corrupted doc).

## Build sequence — six dev / review / test cycles

Each cycle gets its own dev → code-review → test loop and its own feature
branch, per feature-branch discipline.

| Cycle | Deliverable | Test gate |
|---|---|---|
| 1 | `md-min` stripper: tiers 0–1; tier-1 hard-break token-array profiling | snapshot + token-savings tests; profiling shows tier 1 genuinely reduces tokens; `cargo test` green |
| 2 | tiers 2–4 added | per-tier snapshot tests |
| 3 | validation layers L1 (AST allowed-mutation) + L2 (flattened-text equivalence) as deterministic Rust tests | every tier passes L1/L2 with its declared deletions |
| 4 | harness scaffold: corpus (private/real + synthetic + negative control) + HTML render + QA generation (semantic + adversarial + long-range) + frozen QA set | corpus/QA regenerate byte-stable; QA JSON validates; negative control present |
| 5 | council orchestration + response cache + scoring: L3, L4, L5, L6 | `smoke` run: all three CLIs + judge respond; negative control flagged lossy |
| 6 | statistics (paired non-inferiority + Holm–Bonferroni) + report + full benchmark run | report emitted with confidence intervals; verdict computed; negative-control gate passed |

## Success criteria

- The harness produces a reproducible verdict identifying the highest strip
  tier with zero statistically significant inference-quality impact (paired
  non-inferiority, corrected for multiple comparisons), and the token
  savings that tier delivers.
- The negative-control document is correctly flagged as lossy on every run.
- `md-min` passes L1/L2 for every tier with its declared deletions, and has
  snapshot coverage for every tier.
- The report — including `md-min` latency — is committed as a research
  deliverable, sufficient to decide whether, and at which tier, a future
  in-path rollout is warranted.
