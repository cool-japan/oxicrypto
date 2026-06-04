#!/usr/bin/env python3
"""
bench_summary.py — Criterion JSON → Markdown throughput summary table.

Usage
-----
    # Run benchmarks first:
    cargo bench -p oxicrypto-bench 2>/dev/null

    # Generate summary:
    python3 scripts/bench_summary.py

    # Save to file:
    python3 scripts/bench_summary.py > benchmark_summary.md

    # Filter to a specific benchmark group prefix:
    python3 scripts/bench_summary.py --filter aead

Description
-----------
Post-processes the Criterion JSON files written to
  target/criterion/<bench-group>/<bench-id>/estimates.json
and produces a Markdown table with columns:

  | Benchmark | Mean (ns) | Std Dev (ns) | Throughput (MiB/s) |

Throughput is only shown when the benchmark was run with
Criterion's Throughput::Bytes mode (in which case Criterion
also writes a throughput field in the estimates JSON).

Criterion stores estimates under:
  target/criterion/<group>/<function>/<parameter>/estimates.json

The script walks the entire criterion output directory and
collects all estimates.json files, then sorts by group/name.
"""

import argparse
import json
import os
import sys
from pathlib import Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def find_criterion_dir() -> Path:
    """Locate the Criterion output directory relative to the workspace root."""
    # Walk up from cwd until we find target/criterion or Cargo.toml (workspace).
    cwd = Path.cwd()
    candidates = [cwd, cwd.parent, cwd.parent.parent]
    for base in candidates:
        candidate = base / "target" / "criterion"
        if candidate.is_dir():
            return candidate
    # Fallback: relative to this script's location.
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


def throughput_mib_s(bytes_processed: int, time_ns: float) -> float:
    """Compute throughput in MiB/s."""
    if time_ns <= 0:
        return 0.0
    return (bytes_processed / (time_ns * 1e-9)) / (1024 * 1024)


def load_estimates(estimates_path: Path) -> dict:
    """Load and return Criterion estimates.json."""
    with estimates_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def bench_name_from_path(estimates_path: Path, criterion_dir: Path) -> str:
    """
    Derive a benchmark name from the path to estimates.json.

    Criterion layout:
      target/criterion/<group>/<function>/<parameter>/estimates.json
    or:
      target/criterion/<group>/<function>/estimates.json (no parameter)
    """
    rel = estimates_path.relative_to(criterion_dir)
    parts = list(rel.parts[:-1])  # drop estimates.json
    return "/".join(parts)


def collect_benchmarks(criterion_dir: Path, name_filter: str = "") -> list[dict]:
    """
    Walk criterion output directory and collect all benchmark results.

    Returns a list of dicts with keys:
      name, mean_ns, std_dev_ns, bytes_processed, throughput_mib_s
    """
    results = []

    for estimates_path in sorted(criterion_dir.rglob("estimates.json")):
        # Skip "report" directories produced by Criterion's HTML generator.
        if "report" in str(estimates_path):
            continue

        name = bench_name_from_path(estimates_path, criterion_dir)

        if name_filter and name_filter.lower() not in name.lower():
            continue

        try:
            data = load_estimates(estimates_path)
        except (json.JSONDecodeError, OSError):
            continue

        # Criterion estimates.json structure (Criterion 0.5+):
        # { "mean": {"point_estimate": <ns>, "standard_error": <ns>, ...},
        #   "std_dev": {"point_estimate": <ns>, ...},
        #   "throughput": {"bytes_per_second": <f64>} (optional)
        # }
        mean_data = data.get("mean", {})
        std_data = data.get("std_dev", {})
        throughput_data = data.get("throughput")

        mean_ns = mean_data.get("point_estimate", 0.0)
        std_ns = std_data.get("point_estimate", 0.0)

        tp_mib_s = None
        if throughput_data:
            # Criterion 0.5 stores bytes_per_second directly.
            bps = throughput_data.get("bytes_per_second")
            if bps and bps > 0:
                tp_mib_s = bps / (1024 * 1024)

        results.append(
            {
                "name": name,
                "mean_ns": mean_ns,
                "std_dev_ns": std_ns,
                "throughput_mib_s": tp_mib_s,
            }
        )

    return results


def format_markdown_table(results: list[dict]) -> str:
    """Format results as a Markdown table."""
    if not results:
        return "_No benchmark results found._\n"

    has_throughput = any(r["throughput_mib_s"] is not None for r in results)

    header_cols = ["Benchmark", "Mean", "Std Dev"]
    sep_cols = [":---", "---:", "---:"]
    if has_throughput:
        header_cols.append("Throughput")
        sep_cols.append("---:")

    lines = []
    lines.append("| " + " | ".join(header_cols) + " |")
    lines.append("| " + " | ".join(sep_cols) + " |")

    for r in results:
        mean_str = ns_to_human(r["mean_ns"])
        std_str = ns_to_human(r["std_dev_ns"])
        row = [r["name"], mean_str, std_str]
        if has_throughput:
            tp = r["throughput_mib_s"]
            row.append(f"{tp:.1f} MiB/s" if tp is not None else "-")
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines) + "\n"


def format_grouped_markdown(results: list[dict]) -> str:
    """
    Format results grouped by top-level benchmark group (first path component).
    """
    if not results:
        return "_No benchmark results found._\n"

    groups: dict[str, list[dict]] = {}
    for r in results:
        top = r["name"].split("/")[0]
        groups.setdefault(top, []).append(r)

    output_parts = []
    for group_name in sorted(groups):
        group_results = groups[group_name]
        output_parts.append(f"## {group_name}\n")
        output_parts.append(format_markdown_table(group_results))

    return "\n".join(output_parts)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert Criterion JSON output to a Markdown throughput summary table."
    )
    parser.add_argument(
        "--filter",
        default="",
        metavar="PREFIX",
        help="Only include benchmarks whose name contains PREFIX (case-insensitive).",
    )
    parser.add_argument(
        "--flat",
        action="store_true",
        help="Output a single flat table instead of grouped tables.",
    )
    parser.add_argument(
        "--criterion-dir",
        default="",
        metavar="PATH",
        help="Path to the criterion output directory (default: auto-detect).",
    )
    args = parser.parse_args()

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
        print("Run 'cargo bench -p oxicrypto-bench' to generate benchmark data.",
              file=sys.stderr)
        return 1

    results = collect_benchmarks(criterion_dir, name_filter=args.filter)

    if not results:
        print("No benchmark results found. Run 'cargo bench -p oxicrypto-bench' first.",
              file=sys.stderr)
        return 1

    if args.flat:
        print(format_markdown_table(results))
    else:
        print("# OxiCrypto Benchmark Summary\n")
        print(format_grouped_markdown(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
