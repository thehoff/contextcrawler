# md-min — Markdown Minification Viability Design

**Date:** 2026-05-21
**Status:** Approved design — pending implementation plan
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

- TOON / structured-data encodings. TOON is a JSON-data-model format; it
  is the wrong tool for prose documents and was explicitly rejected.
- In-path automatic rewriting of `read`/`cat` on `.md` files. Deferred to
  a future spec, contingent on this benchmark's result.
- Lossy summarisation. The feature is lossless compression only.

## Approach

Build a real Rust markdown minifier (`md-min`) with additive strip tiers,
plus a council-driven viability harness that measures, per tier, token
savings against inference-quality delta across Claude, Codex, and Gemini.
The stripper is genuine production-grade code from day one, so the harness
measures the path that would actually ship — a future in-path rollout is
then just wiring plus a flag, not a re-implementation.

## Components

### 1. `md-min` — Rust markdown minifier

- **Location:** `src/cmds/system/md_min.rs`.
- **Invocation:** explicit subcommand `contextcrawler md-min <file> --tier <0-4>`.
  Explicit only — **not** wired into the `read`/`cat` auto-rewrite path.
- **Implementation:** parses with `pulldown-cmark` (CommonMark, synchronous,
  no async — adds one dependency, plus `pulldown-cmark-to-cmark` for
  re-serialisation) into an event stream; drops or rewrites events per
  tier; re-serialises to markdown. A real parser, not regex — that is what
  makes losslessness provable rather than hoped for.
- **Fallback:** per RTK convention, if parsing fails the original input is
  emitted unchanged; the command never blocks the user.

### 2. Strip tiers

Tiers are **additive** — tier N applies everything tier N-1 does, plus
more. They exist so the harness can locate the *cliff edge*: the highest
tier the council still rates at zero quality impact.

| Tier | Strips | Claim |
|---|---|---|
| **0** | nothing — identity | control / baseline |
| **1** | 3+ blank lines collapse to 1; trailing spaces (hard line breaks converted to backslash form, preserved); table cell padding; HTML comments; list-marker spacing normalised | render-identical, provably lossless |
| **2** | + bold / italic / strikethrough markers (text content kept); horizontal rules | decoration only — text content identical |
| **3** | + heading `#` characters; blockquote `>` markers; link syntax reduced to bare text | the contested hypothesis — markup the model "should not need" |
| **4** | + list markers; code-fence language tags | structure-flattened — expected to lose; included to *prove* the cliff exists |

**Notes on contested cases:**

- Tier 1 is the safe floor. Hard line breaks (trailing two spaces) are
  *converted*, not deleted — `  \n` becomes `\\\n` (backslash form),
  shorter and explicit, so the render is unchanged.
- Heading *level* (h1 vs h3) and list *nesting depth* are document-outline
  information. Tier 3 strips heading hashes and tier 4 strips list markers;
  these are the points where comprehension loss is most plausible. The
  harness exists to settle this — the design does not pre-judge it.

### 3. Viability harness

- **Location:** `harness/md-viability/` — a research harness, not
  production code.
- **Orchestrator language:** Python (concise glue for invoking three CLIs,
  statistics, and scoring; it is a measurement tool, not a shipped path).

**Pipeline:**

1. **Corpus** — `harness/md-viability/corpus/`: roughly 10–15 large
   documents. The bulk are **Wikipedia articles** fetched via the
   Wikipedia REST API (prior art: erictherobot/wikipedia-markdown-generator,
   MIT). Wikipedia is chosen because articles are large, factual (clean,
   verifiable QA ground truth), markup-dense (headings, tables, lists,
   links, emphasis — the exact surface tier 3/4 stresses), license-clean
   (CC BY-SA), and reproducible. Each article is **pinned to a specific
   revision id** (`oldid`) so the corpus does not drift as Wikipedia is
   edited. For each article the fetch step stores **both** the source
   HTML and a markdown conversion. Article titles are chosen to span
   prose-heavy, table-heavy, list/nested-heavy, and mixed structure.
   2–3 real technical documents (long READMEs, `docs/` trees) are also
   included as a representativeness check, since the eventual production
   use case is an agent reading project docs rather than encyclopedia
   articles; these are markdown-only (no HTML source).
2. **QA generation** — one model generates, per document and derived from
   the **raw (tier-0)** document, two question sets: approximately K=15
   *retrieval* question/answer pairs (L3) and a smaller set of *adversarial
   structure probes* (L4) targeting section hierarchy, list order /
   membership / count, and emphasis-carried meaning. Both sets are frozen
   to `qa/<doc>.json` and committed — **identical across all tiers and
   formats**, which is what makes the comparison fair and reproducible.
   One-time step, human-reviewable.
3. **Strip** — run `contextcrawler md-min` over each document at each tier.
4. **Council inference** — every (document, format, question) triple is
   sent to all three council members: `claude`, `codex`, `gemini`. The
   **format ladder** is: source HTML (Wikipedia articles only) → markdown
   tier 0 → tiers 1–4. Source HTML sits above tier 0 as a baseline
   ceiling — it quantifies the cost of HTML and confirms markdown
   conversion is worthwhile at all; the headline comparison remains
   tier 0 versus tiers 1–4. Order of magnitude: 3 models x ~12 documents
   x ~6 formats x ~15 questions is roughly 3,200 calls per full run.
5. **Scoring** — an LLM-as-judge grades each answer against the ground
   truth; accuracy is the percentage correct per (model, tier).
6. **Token metric** — `tiktoken o200k_base` is the stable cross-model
   proxy. Exact per-model token counts vary; savings *ratios* are stable
   across tokenisers, and the ratio is the figure of merit.

### 4. Validation layer

Losslessness is the entire point of the feature, so it is established by
**six independent checks**, not one metric. A tier is declared lossless
only if it passes *every* layer. The two deterministic layers run first
and cost nothing — they catch gross stripper bugs before any council call
is spent. The four behavioural layers attack comprehension loss from
independent angles.

| Layer | Method | Catches | Cost |
|---|---|---|---|
| **L1 — Structural AST equivalence** | Parse raw and stripped, compare normalised ASTs. Each tier *declares* the deletions it is permitted; anything else dropped is a hard fail. | Stripper bugs — accidental structure loss | deterministic |
| **L2 — Content-set preservation** | Extract every atomic content token — body words, numbers, URLs, code identifiers, table cell values — from raw and stripped; assert no *content* token is lost (only markup removed). | A dropped number, a mangled identifier | deterministic |
| **L3 — Retrieval QA accuracy** | Council answers random retrieval QA; accuracy delta versus tier 0. | General comprehension loss | council |
| **L4 — Adversarial structure probes** | QA aimed specifically at what each tier endangers — section hierarchy, list order / membership / count, emphasis-carried meaning. | Subtle structural loss random QA misses | council |
| **L5 — Free-recall divergence** | A model summarises raw versus stripped; the judge flags any fact present in the raw summary that is absent or altered in the stripped one. | Information loss never probed by QA | council + judge |
| **L6 — Cross-model agreement** | Information loss widens model disagreement — measure inter-model answer agreement, raw versus stripped. A drop is a warning flag. | Ambiguity introduced by stripping | computed from L3/L4 |

**Verdict rule:** a tier *passes* only if L1 and L2 are clean (hard,
deterministic) **and** L3, L4, L5 show no statistically significant
degradation versus tier 0 **and** L6 does not flag. "No significant
degradation" is operationalised as accuracy delta within noise — accuracy
delta >= -1% on all three models, or no statistically significant drop
given the per-tier sample (~180 questions per model). The benchmark's
output is "the highest passing tier, and the token savings it delivers."

### 5. Report

- **Location:** `harness/md-viability/reports/md-viability-YYYY-MM-DD.md`.
- **Contents:** token savings and per-model accuracy for every rung of the
  format ladder (source HTML, markdown tiers 0–4), accuracy delta versus
  tier 0, the source-HTML baseline for reference, the computed verdict,
  and a recommendation on what, if anything, should be wired into the
  rewrite path.
- It is a first-class research deliverable — it is the artifact that gates
  the future in-path spec.

## Data flow

```
Wikipedia REST API (pinned oldid) ──> corpus/*.html  +  corpus/*.md
technical docs ──────────────────────────────────────> corpus/*.md
     │
     ├──> QA generation (one model, raw doc) ──> qa/*.json  (frozen)
     │
     └──> md-min --tier 0..4 ──> stripped variants ───┐
                                  + source HTML ──────┤
                                                      │
qa/*.json ───────────────────────────────────────────┤
                                                      ▼
                                    council inference (claude, codex, gemini)
                                                      │
                                                      ▼
                                    LLM-as-judge scoring  +  tiktoken counts
                                                      │
                                                      ▼
                              reports/md-viability-YYYY-MM-DD.md  (verdict)
```

## Error handling

- **Stripper:** parse failure emits the original input unchanged (RTK
  fallback convention); a malformed tier argument is a hard usage error.
- **Harness:** a failed council call is retried with backoff, then recorded
  as a missing data point rather than aborting the run; the report states
  the completeness of each cell.
- **Judge:** an unparseable judge verdict is retried once, then recorded as
  ungraded and excluded from the accuracy denominator, with the exclusion
  count surfaced in the report.

## Testing

- **Stripper:** snapshot tests (`insta`) per tier on real fixtures;
  token-savings assertions. Validation layers **L1 (AST equivalence)** and
  **L2 (content-set preservation)** are implemented as deterministic Rust
  tests over the corpus — they run in `cargo test`, per tier.
- **Harness:** QA JSON schema validation; a single-document dry run that
  confirms all three CLIs respond and the judge scores; reproducibility
  check (frozen QA set produces identical inputs across runs).

## Build sequence — six dev / review / test cycles

Each cycle gets its own dev → code-review → test loop and its own feature
branch, per feature-branch discipline.

| Cycle | Deliverable | Test gate |
|---|---|---|
| 1 | `md-min` stripper: tiers 0–1 | snapshot + token-savings tests; `cargo test` green |
| 2 | tiers 2–4 added | per-tier snapshot tests |
| 3 | validation layers L1 (AST equivalence) + L2 (content-set preservation) as deterministic Rust tests | every tier passes L1/L2 with its declared deletions, or the failure is understood |
| 4 | harness scaffold: corpus fetch (Wikipedia REST API, pinned `oldid`, HTML + markdown) + QA generation (retrieval + adversarial L4) + frozen QA set | corpus re-fetch is byte-stable; QA JSON validates |
| 5 | council orchestration + scoring: L3 retrieval QA, L4 adversarial probes, L5 free-recall divergence, L6 agreement | dry run on one document; all three CLIs respond; judge scores |
| 6 | report generation + full benchmark run | report emitted; verdict computed across all six layers |

## Success criteria

- The harness produces a reproducible verdict identifying the highest
  strip tier with zero statistically significant inference-quality impact,
  and the token savings that tier delivers.
- The `md-min` stripper passes its lossless assertion for tier 1 and has
  snapshot coverage for every tier.
- The report is committed as a research deliverable and is sufficient to
  decide whether — and at which tier — a future in-path rollout is
  warranted.
