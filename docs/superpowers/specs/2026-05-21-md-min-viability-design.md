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

1. **Corpus** — `harness/md-viability/corpus/`: roughly 10–15 large, real
   markdown documents, version-controlled, deliberately varied across
   prose-heavy, table-heavy, list/nested-heavy, code-heavy, and mixed
   structure. Sourced from real documents (long READMEs, `docs/` trees,
   CHANGELOGs, technical specification documents).
2. **QA generation** — one model generates approximately K=15 retrieval
   question/answer pairs per document, derived from the **raw (tier-0)**
   document. The set is frozen to `qa/<doc>.json` and committed. The QA
   set is **identical across all tiers** — that is what makes the
   comparison fair and reproducible. One-time step, human-reviewable.
3. **Strip** — run `contextcrawler md-min` over each document at each tier.
4. **Council inference** — every (document, tier) pair, with each question,
   is sent to all three council members: `claude`, `codex`, `gemini`.
   Order of magnitude: 3 models x ~12 documents x 5 tiers x ~15 questions
   is roughly 2,700 calls per full run.
5. **Scoring** — an LLM-as-judge grades each answer against the ground
   truth; accuracy is the percentage correct per (model, tier).
6. **Token metric** — `tiktoken o200k_base` is the stable cross-model
   proxy. Exact per-model token counts vary; savings *ratios* are stable
   across tokenisers, and the ratio is the figure of merit.

**Verdict rule:** a tier *passes* if its accuracy delta versus tier 0 is
within noise — operationally, accuracy delta >= -1% on all three models,
or no statistically significant drop given the per-tier sample of roughly
180 questions per model. The benchmark's output is "the highest passing
tier, and the token savings it delivers."

### 4. Report

- **Location:** `harness/md-viability/reports/md-viability-YYYY-MM-DD.md`.
- **Contents:** per-tier token savings; per-model accuracy and delta versus
  tier 0; the computed verdict; and a recommendation on what, if anything,
  should be wired into the rewrite path.
- It is a first-class research deliverable — it is the artifact that gates
  the future in-path spec.

## Data flow

```
corpus/*.md ──> QA generation (one model, raw doc) ──> qa/*.json  (frozen)
     │
     └──> md-min --tier 0..4 ──> stripped variants ──┐
                                                     │
qa/*.json ──────────────────────────────────────────┤
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
  token-savings assertions; an explicit lossless-assertion for tier 1
  (parse the stripped output, confirm the rendered HTML / normalised AST
  matches the raw document).
- **Harness:** QA JSON schema validation; a single-document dry run that
  confirms all three CLIs respond and the judge scores; reproducibility
  check (frozen QA set produces identical inputs across runs).

## Build sequence — five dev / review / test cycles

Each cycle gets its own dev → code-review → test loop and its own feature
branch, per feature-branch discipline.

| Cycle | Deliverable | Test gate |
|---|---|---|
| 1 | `md-min` stripper: tiers 0–1 | snapshot + token-savings tests; `cargo test` green |
| 2 | tiers 2–4 added | per-tier snapshot tests; tier-1 lossless assertion |
| 3 | harness scaffold: corpus + QA generation + frozen QA set | QA JSON validates; reproducible |
| 4 | council orchestration + scoring | dry run on one document; all three CLIs respond; judge scores |
| 5 | report generation + full benchmark run | report emitted; verdict computed |

## Success criteria

- The harness produces a reproducible verdict identifying the highest
  strip tier with zero statistically significant inference-quality impact,
  and the token savings that tier delivers.
- The `md-min` stripper passes its lossless assertion for tier 1 and has
  snapshot coverage for every tier.
- The report is committed as a research deliverable and is sufficient to
  decide whether — and at which tier — a future in-path rollout is
  warranted.
