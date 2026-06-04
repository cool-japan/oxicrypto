#!/usr/bin/env python3
"""
bench_ratios.py — Compute OxiCrypto / ring performance ratios from Criterion JSON.

Usage
-----
    # Run benchmarks first (hash binary contains ring comparison groups):
    cargo bench -p oxicrypto-bench --bench hash 2>/dev/null

    # Compute ratios:
    python3 scripts/bench_ratios.py

    # Save to file:
    python3 scripts/bench_ratios.py > bench_ratios.md

    # Show only comparisons exceeding a threshold ratio:
    python3 scripts/bench_ratios.py --warn-above 1.5

Description
-----------
Reads Criterion JSON files from target/criterion/ and identifies benchmark
pairs where one sub-benchmark is "oxicrypto" and another is "ring" (or
"aws-lc-rs") under the same group.  Computes the ratio:

    ratio = oxicrypto_mean_ns / baseline_mean_ns

A ratio < 1.0 means OxiCrypto is faster than the baseline.
A ratio > 1.0 means OxiCrypto is slower than the baseline.

Regression thresholds (configurable via --warn-above):
    - AES-GCM    : warn if ratio > 1.5x ring
    - ChaCha20   : warn if ratio > 1.1x ring
    - SHA-256    : warn if ratio > 2.0x ring
    - Ed25519    : warn if ratio > 2.0x ring

Output format: Markdown table with columns:
    | Algorithm | Size | OxiCrypto (µs) | ring (µs) | Ratio | Status |
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

# ── Default regression thresholds ─────────────────────────────────────────────
#
# Map from a pattern (matched against the benchmark group path) to the maximum
# acceptable ratio (OxiCrypto / ring).  Override via --warn-above.

DEFAULT_THRESHOLDS: dict[str, float] = {
    "aes.*gcm": 1.5,
    "chacha20": 1.1,
    "sha.256": 2.0,
    "sha.512": 2.0,
    "ed25519": 2.0,
    "ecdsa": 2.0,
    "x25519": 2.0,
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def find_criterion_dir() -> Path:
    """Locate the Criterion output directory relative to cwd or script location."""
    cwd = Path.cwd()
    candidates = [cwd, cwd.parent, cwd.parent.parent]
    for base in candidates:
        candidate = base / "target" / "criterion"
        if candidate.is_dir():
            return candidate
    script_dir = Path(__file__).parent
    for base in [script_dir.parent, script_dir.parent.parent]:
        candidate = base / "target" / "criterion"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "Cannot find target/criterion directory. "
        "Run 'cargo bench -p oxicrypto-bench' first."
    )


def ns_to_human(ns: float) -> str:
    """Format nanoseconds as a human-readable string."""
    if ns < 1_000:
        return f"{ns:.1f} ns"
    elif ns < 1_000_000:
        return f"{ns / 1_000:.2f} µs"
    else:
        return f"{ns / 1_000_000:.2f} ms"


def load_criterion_benchmarks(criterion_dir: Path) -> dict[str, float]:
    """
    Walk the criterion directory and return a dict mapping benchmark path to
    mean latency in nanoseconds.

    Path format: <group>/<function>/<parameter>
    Example: "hash_vs_ring/SHA-256/oxicrypto/1024" → mean_ns
    """
    results: dict[str, float] = {}

    for est_path in sorted(criterion_dir.rglob("estimates.json")):
        if "report" in str(est_path):
            continue
        rel = est_path.relative_to(criterion_dir)
        parts = list(rel.parts[:-1])  # drop "estimates.json"
        key = "/".join(parts)

        try:
            with est_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        mean_ns = data.get("mean", {}).get("point_estimate", 0.0)
        if mean_ns > 0:
            results[key] = mean_ns

    return results


def find_comparison_pairs(
    benchmarks: dict[str, float],
) -> list[dict]:
    """
    Identify (oxicrypto, ring, aws-lc-rs) pairs within the same group.

    Returns a list of dicts:
      { group, param, oxi_key, oxi_ns, baseline, baseline_key, baseline_ns }
    """
    pairs: list[dict] = []

    # Collect by group prefix: strip the last two components (function + param).
    # Criterion layout: group/function/param/estimates.json
    # We search for paths whose final function component is "oxicrypto" or "ring".

    # Build a map: (group_prefix + "/" + param) → {impl: mean_ns}
    grouped: dict[str, dict[str, float]] = {}

    for key, mean_ns in benchmarks.items():
        parts = key.split("/")
        if len(parts) < 2:
            continue

        impl_name = parts[-2] if len(parts) >= 2 else ""
        param_val = parts[-1] if len(parts) >= 1 else ""
        group_prefix = "/".join(parts[:-2])

        canonical_key = f"{group_prefix}/{param_val}"
        grouped.setdefault(canonical_key, {})[impl_name] = mean_ns

    for canonical_key, impls in grouped.items():
        oxi_ns = impls.get("oxicrypto")
        ring_ns = impls.get("ring")
        awslc_ns = impls.get("aws-lc-rs")

        if oxi_ns is None:
            continue

        group_prefix, _, param_val = canonical_key.rpartition("/")

        if ring_ns is not None:
            pairs.append(
                {
                    "group": group_prefix,
                    "param": param_val,
                    "oxi_ns": oxi_ns,
                    "baseline": "ring",
                    "baseline_ns": ring_ns,
                }
            )
        if awslc_ns is not None:
            pairs.append(
                {
                    "group": group_prefix,
                    "param": param_val,
                    "oxi_ns": oxi_ns,
                    "baseline": "aws-lc-rs",
                    "baseline_ns": awslc_ns,
                }
            )

    pairs.sort(key=lambda p: (p["group"], p["baseline"], p["param"]))
    return pairs


def threshold_for(group: str, warn_above: Optional[float] = None) -> float:
    """Return the regression threshold for a given group path."""
    if warn_above is not None:
        return warn_above
    group_lower = group.lower()
    for pattern, threshold in DEFAULT_THRESHOLDS.items():
        if re.search(pattern, group_lower):
            return threshold
    # Default: flag anything more than 3x slower than the reference.
    return 3.0


def format_ratio_table(
    pairs: list[dict],
    warn_above: Optional[float],
    show_pass: bool,
) -> tuple[str, int]:
    """
    Format the comparison pairs as a Markdown table.

    Returns (markdown_text, fail_count).
    """
    if not pairs:
        return "_No comparison pairs found.  Run `cargo bench -p oxicrypto-bench --bench hash` first._\n", 0

    header = "| Algorithm | Param | OxiCrypto | Baseline (ring/aws-lc) | Ratio | Status |"
    sep =    "| :--- | ---: | ---: | ---: | ---: | :--- |"

    lines = [header, sep]
    fail_count = 0

    for p in pairs:
        ratio = p["oxi_ns"] / p["baseline_ns"] if p["baseline_ns"] > 0 else float("inf")
        threshold = threshold_for(p["group"], warn_above)
        status = "PASS" if ratio <= threshold else "FAIL"
        if status == "FAIL":
            fail_count += 1

        if not show_pass and status == "PASS":
            continue

        oxi_str = ns_to_human(p["oxi_ns"])
        base_str = f"{ns_to_human(p['baseline_ns'])} ({p['baseline']})"

        status_icon = "OK" if status == "PASS" else "WARN"
        lines.append(
            f"| `{p['group']}` | {p['param']} "
            f"| {oxi_str} | {base_str} "
            f"| {ratio:.2f}x | {status_icon} |"
        )

    return "\n".join(lines) + "\n", fail_count


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute OxiCrypto / ring performance ratios from Criterion JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--warn-above",
        type=float,
        default=None,
        metavar="RATIO",
        help=(
            "Warn (and exit non-zero) when OxiCrypto/baseline ratio exceeds this value "
            "for any comparison.  Overrides per-algorithm defaults."
        ),
    )
    parser.add_argument(
        "--criterion-dir",
        default="",
        metavar="PATH",
        help="Path to the criterion output directory (default: auto-detect).",
    )
    parser.add_argument(
        "--show-pass",
        action="store_true",
        default=True,
        help="Include passing rows in the table (default: true).",
    )
    parser.add_argument(
        "--fail-only",
        action="store_true",
        help="Show only failing rows (overrides --show-pass).",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with status 1 if any comparison exceeds its threshold.",
    )
    args = parser.parse_args()

    show_pass = not args.fail_only

    # Locate criterion output directory.
    if args.criterion_dir:
        criterion_dir = Path(args.criterion_dir)
    else:
        try:
            criterion_dir = find_criterion_dir()
        except FileNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if not criterion_dir.is_dir():
        print(
            f"Error: Criterion output directory does not exist: {criterion_dir}",
            file=sys.stderr,
        )
        print(
            "Run 'cargo bench -p oxicrypto-bench --bench hash' to generate comparison data.",
            file=sys.stderr,
        )
        return 1

    benchmarks = load_criterion_benchmarks(criterion_dir)
    if not benchmarks:
        print(
            "No benchmark results found.  Run 'cargo bench -p oxicrypto-bench' first.",
            file=sys.stderr,
        )
        return 1

    pairs = find_comparison_pairs(benchmarks)
    if not pairs:
        print(
            "No (oxicrypto, ring/aws-lc-rs) comparison pairs found.\n"
            "Make sure you have run the hash/sig/kex benchmarks which include ring comparisons.",
            file=sys.stderr,
        )
        # Not an error — user may not have ring comparison data yet.
        return 0

    print("# OxiCrypto vs ring / aws-lc-rs Performance Ratios\n")
    print(
        "Ratio = OxiCrypto mean latency / baseline mean latency.  "
        "A ratio < 1.0 means OxiCrypto is faster.\n"
    )
    table_text, fail_count = format_ratio_table(pairs, args.warn_above, show_pass)
    print(table_text)

    if fail_count > 0:
        print(
            f"\n**{fail_count} comparison(s) exceeded their regression threshold.**",
            file=sys.stderr,
        )
        if args.fail_on_regression:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
