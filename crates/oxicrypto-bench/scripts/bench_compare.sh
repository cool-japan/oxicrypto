#!/usr/bin/env bash
# bench_compare.sh — Run benchmarks before and after a change and diff the results.
#
# Usage:
#   scripts/bench_compare.sh [BENCH_NAME] [OPTIONS]
#
# Arguments:
#   BENCH_NAME   Optional: run only this benchmark binary (e.g. "aead", "hash").
#                Default: run all bench binaries.
#
# Options:
#   --baseline NAME   Use this name for the "before" snapshot (default: "before").
#   --new-base NAME   Use this name for the "after" snapshot (default: "after").
#   --help            Show this help and exit.
#
# Environment variables:
#   BENCH_QUICK=1     Run with --sample-size=10 for a faster smoke check.
#
# Workflow:
#   1. Stash or commit your changes.
#   2. Run this script to capture the "before" baseline.
#   3. Apply your changes.
#   4. Run this script again — it detects the baseline exists and compares.
#
# The script uses Criterion's built-in baseline comparison mechanism:
#   cargo bench -- --save-baseline <name>
#   cargo bench -- --baseline <before> --save-baseline <after>
#
# Output format: criterion prints percentage changes per measurement.
# This script additionally collates them into a unified summary.
#
# Requirements:
#   - cargo (Rust toolchain in PATH)
#   - Python 3.6+ (for bench_summary.py)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Navigate to the bench crate root (parent of scripts/).
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Navigate to the workspace root (parent of the bench crate).
WORKSPACE_DIR="$(cd "$BENCH_DIR/../.." && pwd)"

BEFORE_BASELINE="before"
AFTER_BASELINE="after"
BENCH_NAME=""
SHOW_HELP=0

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline)
            BEFORE_BASELINE="$2"
            shift 2
            ;;
        --new-base)
            AFTER_BASELINE="$2"
            shift 2
            ;;
        --help|-h)
            SHOW_HELP=1
            shift
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            BENCH_NAME="$1"
            shift
            ;;
    esac
done

if [[ $SHOW_HELP -eq 1 ]]; then
    grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 0
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

info() { printf '\033[34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m[ERR ]\033[0m %s\n' "$*" >&2; }

# ── Determine bench cargo args ────────────────────────────────────────────────

CARGO_BENCH_ARGS=(-p oxicrypto-bench)
if [[ -n "$BENCH_NAME" ]]; then
    CARGO_BENCH_ARGS+=(--bench "$BENCH_NAME")
fi

CRITERION_ARGS=()
if [[ "${BENCH_QUICK:-}" == "1" ]]; then
    warn "BENCH_QUICK=1: using --sample-size=10 for all benchmarks"
    CRITERION_ARGS+=(-- --sample-size=10)
fi

# ── Locate the "before" baseline ─────────────────────────────────────────────

BASELINE_DIR="${WORKSPACE_DIR}/target/criterion"
BEFORE_EXISTS=0
if [[ -d "${BASELINE_DIR}" ]]; then
    # Check if any estimates.json exists under a directory named $BEFORE_BASELINE.
    if find "${BASELINE_DIR}" -name "estimates.json" -path "*/${BEFORE_BASELINE}/*" \
            -maxdepth 6 -quit 2>/dev/null | grep -q .; then
        BEFORE_EXISTS=1
    fi
fi

# ── Run benchmarks ────────────────────────────────────────────────────────────

cd "$WORKSPACE_DIR"

if [[ $BEFORE_EXISTS -eq 0 ]]; then
    info "No '${BEFORE_BASELINE}' baseline found — capturing baseline now."
    info "After applying your changes, run this script again to compare."
    info ""
    info "Running: cargo bench ${CARGO_BENCH_ARGS[*]} ${CRITERION_ARGS[*]} --save-baseline ${BEFORE_BASELINE}"
    cargo bench "${CARGO_BENCH_ARGS[@]}" \
        "${CRITERION_ARGS[@]}" \
        -- --save-baseline "${BEFORE_BASELINE}"
    ok "Baseline '${BEFORE_BASELINE}' saved to ${BASELINE_DIR}."
    info "Apply your changes, then run this script again."
else
    info "Baseline '${BEFORE_BASELINE}' found — comparing against new run."
    info ""
    info "Running: cargo bench ${CARGO_BENCH_ARGS[*]} -- --baseline ${BEFORE_BASELINE} --save-baseline ${AFTER_BASELINE}"
    cargo bench "${CARGO_BENCH_ARGS[@]}" \
        -- --baseline "${BEFORE_BASELINE}" --save-baseline "${AFTER_BASELINE}"

    info ""
    ok "Comparison complete.  Criterion HTML report:"
    info "  file://${BASELINE_DIR}/report/index.html"
    info ""
    info "Generating Markdown summary of '${AFTER_BASELINE}' results..."
    if command -v python3 &>/dev/null; then
        python3 "${SCRIPT_DIR}/bench_summary.py" --flat 2>/dev/null || true
    else
        warn "python3 not found — skipping Markdown summary."
    fi
fi
