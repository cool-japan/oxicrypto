#!/usr/bin/env bash
# bench_simd_compare.sh — Compare OxiCrypto throughput with and without SIMD.
#
# Usage:
#   scripts/bench_simd_compare.sh [BENCH_NAME]
#
# Arguments:
#   BENCH_NAME   Optional: run only this benchmark binary (e.g. "aead", "hash").
#                Default: run the "aead" and "hash" binaries (most sensitive to SIMD).
#
# Options:
#   --help    Show this help and exit.
#
# Description:
#   Runs `cargo bench` twice for the specified benchmark(s):
#
#     1. With oxicrypto features = ["pure", "simd"]   (SIMD enabled)
#     2. With oxicrypto features = ["pure"]            (SIMD disabled)
#
#   The comparison uses Criterion's baseline mechanism:
#     - First run saves baseline "simd-on"
#     - Second run saves baseline "simd-off" and loads "simd-on" for comparison
#
#   Criterion prints percentage changes inline.  The script additionally
#   generates Markdown summary tables for both runs.
#
# Workspace notes:
#   oxicrypto-bench's Cargo.toml hardcodes `oxicrypto = { features = ["pure","simd"] }`.
#   Disabling simd requires a temporary RUSTFLAGS override that prevents LLVM
#   from emitting AVX2/SHA-NI/NEON instructions:
#
#     RUSTFLAGS="-C target-feature=-avx2,-sha,-neon,-sse4.1"
#
#   This is a best-effort approximation; it does not disable the `simd` feature
#   flag at the crate level (which would require editing Cargo.toml).  For a
#   precise test, manually edit Cargo.toml to remove "simd" from the features list.
#
# Requirements:
#   - cargo (Rust toolchain in PATH)
#   - Python 3.6+ (for bench_summary.py)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$BENCH_DIR/../.." && pwd)"

BENCH_NAME=""
SHOW_HELP=0

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
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

# Default bench targets: aead and hash are most SIMD-sensitive.
if [[ -z "$BENCH_NAME" ]]; then
    BENCH_TARGETS=("aead" "hash")
else
    BENCH_TARGETS=("$BENCH_NAME")
fi

cd "$WORKSPACE_DIR"

# ── Determine RUSTFLAGS for "no SIMD" run ─────────────────────────────────────
#
# Architecture-specific flags to disable the most impactful SIMD extensions.
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)
        NO_SIMD_FLAGS="-C target-feature=-avx2,-avx,-sha,-sse4.2,-sse4.1,-ssse3,-sse3,-aes"
        ;;
    arm64|aarch64)
        NO_SIMD_FLAGS="-C target-feature=-neon,-crypto,-sha2,-aes,-sha3"
        ;;
    *)
        warn "Unknown architecture ${ARCH}; RUSTFLAGS no-SIMD approximation may be incomplete."
        NO_SIMD_FLAGS="-C target-feature=-avx2,-sha,-neon"
        ;;
esac

# ── Run with SIMD enabled ─────────────────────────────────────────────────────

info "Phase 1/2: Benchmarks WITH SIMD (baseline: simd-on)"
for bench in "${BENCH_TARGETS[@]}"; do
    ARGS=(-p oxicrypto-bench --bench "$bench")
    info "  Running: cargo bench ${ARGS[*]} -- --save-baseline simd-on"
    cargo bench "${ARGS[@]}" -- --save-baseline simd-on
    ok "  Saved baseline 'simd-on' for bench: ${bench}"
done

# ── Run without SIMD ──────────────────────────────────────────────────────────

info ""
info "Phase 2/2: Benchmarks WITHOUT SIMD (RUSTFLAGS='${NO_SIMD_FLAGS}')"
for bench in "${BENCH_TARGETS[@]}"; do
    ARGS=(-p oxicrypto-bench --bench "$bench")
    info "  Running: RUSTFLAGS='...' cargo bench ${ARGS[*]} -- --baseline simd-on --save-baseline simd-off"
    RUSTFLAGS="$NO_SIMD_FLAGS" cargo bench "${ARGS[@]}" \
        -- --baseline simd-on --save-baseline simd-off
    ok "  Saved baseline 'simd-off' for bench: ${bench}; comparison complete."
done

# ── Generate summary tables ────────────────────────────────────────────────────

info ""
info "Generating Markdown summary tables..."
CRITERION_DIR="${WORKSPACE_DIR}/target/criterion"

if command -v python3 &>/dev/null && [[ -d "$CRITERION_DIR" ]]; then
    echo ""
    echo "## SIMD-on benchmark summary"
    python3 "${SCRIPT_DIR}/bench_summary.py" \
        --criterion-dir "$CRITERION_DIR" 2>/dev/null || true

    ok "Criterion HTML reports:"
    info "  file://${CRITERION_DIR}/report/index.html"
else
    warn "python3 not found or criterion dir missing; skipping Markdown summary."
fi

info ""
ok "SIMD comparison complete."
info "To interpret: look for benches where 'simd-off' is significantly slower than 'simd-on'."
info "Those are the algorithms that benefit most from hardware acceleration."
