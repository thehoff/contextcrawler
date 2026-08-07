#!/usr/bin/env python3
"""Extract a scrubbed, replayable FP corpus from the downgrade telemetry.

The gate's correctness has been judged by "can a reviewer imagine a bypass?"
That question is unbounded, which is why #2286 took four rounds and the #191
false-positive suppressor took eight. This produces the missing number: replay
real traffic through the in-tree suppression layer and count what it catches.

`downgrades.jsonl` records `(cmd, tirith)` pairs, which are exactly the inputs
to `tirith_gate::should_downgrade_for_command`. Capturing the Tirith verdict
JSON alongside the command makes replay hermetic — CI needs no Tirith binary.

Usage:
    scripts/extract-gate-corpus.py [--log PATH] [--out PATH] [--verify]

    --verify  scrub-check an existing corpus and exit non-zero if it leaks.

The raw log is NOT committable. As at 2026-08-07 it held 2,009 records naming
the author's home directory, 683 internal hostnames, 354 RFC1918 addresses and
71 credential-shaped literals that `core::secret_redact::redact` does not cover
(it handles PEM blocks, URL userinfo, Authorization headers, GH tokens and
secret *paths* — not inline `token=<value>`). Everything here exists to make
the output safe to track. Read the diff before committing a regenerated corpus.

Refs: #243
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

DEFAULT_LOG = Path.home() / ".local/share/contextcrawler/downgrades.jsonl"
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "tests/fixtures/gate_corpus.jsonl"

# One day of #191 development ran a corpus through the gate: 3,481 of 4,232
# events. Including it makes organic traffic look 5.6x worse than it is — the
# exact error this corpus exists to prevent, so it is excluded by name.
DEV_CORPUS_DAYS = {"2026-07-12"}

# ─── Scrubbing ──────────────────────────────────────────────────────────────
# Order matters: narrow patterns first, so a broad one cannot swallow the text
# a narrow one would have labelled more precisely.

SCRUBBERS: list[tuple[re.Pattern[str], str]] = [
    # Credential-shaped key=value / key: value. Value replaced wholesale.
    (
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|token|password|passwd|secret|bearer)"
            r"(\"?\s*[=:]\s*\"?)"
            r"[A-Za-z0-9_/+.=-]{3,}"
        ),
        r"\1\2SCRUBBED",
    ),
    # Authorization headers, whatever the scheme.
    (re.compile(r"(?i)(authorization\s*:\s*\S+\s+)\S+"), r"\1SCRUBBED"),
    # URL userinfo (user:pass@host).
    (re.compile(r"(https?://)[^:\s/@]+:[^@\s/]+@"), r"\1SCRUBBED@"),
    # Home directories, both platforms. Keeps path *shape*, which is what the
    # gate reasons about, while dropping the identity.
    (re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+"), "/home/user"),
    # The username also appears OUTSIDE a home prefix and survives the rule
    # above: `/home/user/Personas/thehoff/code/...`, `~/Personas/thehoff/...`,
    # and Claude's path-mangled scratch dirs (`-home-thehoff-Personas-thehoff-`).
    # Caught by eyeballing the first generated corpus, not by the leak checks —
    # which is exactly why this script tells you to read the diff.
    # Substituted in `build_identity_scrubbers()` because the token is derived
    # at runtime rather than hardcoded.
    # RFC1918 + loopback-adjacent literals -> a stable placeholder per class,
    # because several rules (raw_ip_url, private_network_access) key on shape.
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "10.0.0.1"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "192.168.0.1"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), "172.16.0.1"),
    # Internal hostnames.
    (re.compile(r"\b[A-Za-z0-9-]+\.h\.hoff-network\.com\b"), "host.internal.example"),
    (re.compile(r"\b[A-Za-z0-9-]+\.hoff-network\.com\b"), "host.internal.example"),
    (re.compile(r"\b[A-Za-z0-9-]+\.thehoff\.group\b"), "host.internal.example"),
    (re.compile(r"\b[A-Za-z0-9-]+\.service-now\.com\b"), "instance.service-now.example"),
    # Session UUIDs in scratch paths — high cardinality, zero analytic value.
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        "00000000-0000-0000-0000-000000000000",
    ),
]

# Applied AFTER scrubbing. A hit means the scrubbers missed something; the
# record is dropped rather than shipped, because a corpus that leaks once is
# worse than a corpus that is slightly smaller.
LEAK_CHECKS: list[tuple[str, re.Pattern[str]]] = [
    ("home path", re.compile(r"/(?:home|Users)/(?!user\b)[A-Za-z0-9._-]+")),
    # Must be a full dotted quad. An earlier version matched `10.` + digits and
    # discarded 30 good records whose commands contained timing decimals like
    # `10.209643`. The placeholders the scrubbers emit are excluded by name.
    ("private ip", re.compile(
        r"\b(?!10\.0\.0\.1\b)(?!192\.168\.0\.1\b)(?!172\.16\.0\.1\b)"
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
    ("internal host", re.compile(r"(?i)\b[A-Za-z0-9-]+\.(?:hoff-network\.com|thehoff\.group"
                                 r"|service-now\.com)\b")),
    ("credential literal", re.compile(
        r"(?i)\b(?:api[_-]?key|apikey|token|password|passwd|secret|bearer)"
        r"\"?\s*[=:]\s*\"?(?!SCRUBBED)[A-Za-z0-9_/+.=-]{3,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Za-z0-9 ]*PRIVATE KEY-----")),
    ("ssh key path", re.compile(r"\.ssh/id_[A-Za-z0-9]")),
]


# Populated by `configure_identity()`. Kept module-level so `leaks()` can use
# the same token the scrubbers used, rather than a second hardcoded copy.
IDENTITY_SCRUBBERS: list[tuple[re.Pattern[str], str]] = []
IDENTITY_CHECKS: list[tuple[str, re.Pattern[str]]] = []


def configure_identity(username: str) -> None:
    """Scrub a username wherever it appears, not just after a home prefix.

    The first generated corpus leaked `thehoff` via `Personas/<user>/`, `~/…`
    and Claude's mangled scratch dirs. Matching the bare token catches all
    three without needing to enumerate the path shapes that carry it — which
    would be the same enumeration trap this whole exercise is about.
    """
    IDENTITY_SCRUBBERS.clear()
    IDENTITY_CHECKS.clear()
    if not username or len(username) < 3:
        return
    token = re.compile(rf"(?<![A-Za-z0-9]){re.escape(username)}(?![A-Za-z0-9])")
    IDENTITY_SCRUBBERS.append((token, "user"))
    IDENTITY_CHECKS.append(("username", token))


def scrub(text: str) -> str:
    for pattern, replacement in SCRUBBERS:
        text = pattern.sub(replacement, text)
    for pattern, replacement in IDENTITY_SCRUBBERS:
        text = pattern.sub(replacement, text)
    return text


def leaks(text: str) -> list[str]:
    found = [name for name, pattern in LEAK_CHECKS if pattern.search(text)]
    found += [name for name, pattern in IDENTITY_CHECKS if pattern.search(text)]
    return found


def scrub_tirith(node):
    """Recursively scrub every string in the captured Tirith verdict."""
    if isinstance(node, str):
        return scrub(node)
    if isinstance(node, list):
        return [scrub_tirith(item) for item in node]
    if isinstance(node, dict):
        return {key: scrub_tirith(value) for key, value in node.items()}
    return node


def extract(log_path: Path) -> tuple[list[dict], Counter]:
    stats: Counter = Counter()
    seen: set[str] = set()
    corpus: list[dict] = []

    with log_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats["malformed"] += 1
                continue

            stats["read"] += 1

            if (record.get("ts") or "")[:10] in DEV_CORPUS_DAYS:
                stats["skipped_dev_corpus"] += 1
                continue

            # Only Tirith blocks carry the verdict JSON the replay needs.
            tirith = record.get("tirith")
            if record.get("reason") != "tirith_block" or not tirith:
                stats["skipped_no_verdict"] += 1
                continue

            cmd = scrub(record.get("cmd") or "")
            if not cmd.strip():
                stats["skipped_empty"] += 1
                continue

            verdict = scrub_tirith(tirith)
            verdict_json = json.dumps(verdict, sort_keys=True, separators=(",", ":"))

            found = leaks(cmd) + leaks(verdict_json)
            if found:
                stats["dropped_leak"] += 1
                for name in set(found):
                    stats[f"leak:{name}"] += 1
                continue

            # Deduplicate on the exact replay input. The log is dominated by
            # repeated agent commands; 400 copies of one shape teach nothing
            # and would let a single shape dominate the baseline.
            key = f"{cmd}\x00{verdict_json}"
            if key in seen:
                stats["deduped"] += 1
                continue
            seen.add(key)

            rules = sorted({
                finding.get("rule_id", "?")
                for finding in (verdict.get("findings") or [])
                if isinstance(finding, dict)
            })

            corpus.append({
                "cmd": cmd,
                "rules": rules,
                "tirith": verdict_json,
            })
            stats["kept"] += 1

    corpus.sort(key=lambda entry: (entry["rules"], entry["cmd"]))
    return corpus, stats


def verify(path: Path) -> int:
    failures = 0
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            found = leaks(line)
            if found:
                failures += 1
                print(f"  {path.name}:{lineno} leaks {', '.join(found)}", file=sys.stderr)
    if failures:
        print(f"\nFAIL: {failures} corpus line(s) leak private data.", file=sys.stderr)
        return 1
    print(f"OK: {path} is clean.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--verify", action="store_true",
                        help="scrub-check an existing corpus instead of regenerating it")
    parser.add_argument("--username", default=Path.home().name,
                        help="identity token to scrub everywhere (default: $HOME's basename)")
    args = parser.parse_args()

    configure_identity(args.username)

    if args.verify:
        if not args.out.exists():
            print(f"no corpus at {args.out}", file=sys.stderr)
            return 1
        return verify(args.out)

    if not args.log.exists():
        print(f"no telemetry at {args.log}", file=sys.stderr)
        return 1

    corpus, stats = extract(args.log)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for entry in corpus:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    print(f"wrote {len(corpus)} entries -> {args.out}\n")
    for key in sorted(stats):
        print(f"  {stats[key]:>6}  {key}")
    print("\nREAD THE DIFF before committing. The scrubbers are best-effort;")
    print("the leak checks are the backstop, not a guarantee.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
