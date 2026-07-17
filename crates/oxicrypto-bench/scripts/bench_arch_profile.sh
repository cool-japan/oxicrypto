#!/usr/bin/env bash
# bench_arch_profile.sh — Record a native-architecture Criterion baseline.
#
# Usage:
#   scripts/bench_arch_profile.sh [BENCH_NAME ...]
#
# Arguments:
#   BENCH_NAME   Optional benchmark binary name(s) to run (e.g. "aead", "hash").
#                Default: "aead" and "hash" — the SIMD-sensitive groups whose
#                throughput depends most on the host's vector ISA
#                (NEON on aarch64, AES-NI / AVX2 / SHA-NI on x86_64).
#
# Options:
#   --archive          After the run, archive the results with a per-arch label
#                      via bench_archive.sh (baseline tag = "<version>-<arch>").
#   --version VERSION  Version string to pass through to bench_archive.sh.
#   --help             Show this help and exit.
#
# Description:
#   This wrapper records the *native* CPU-architecture baseline for the
#   throughput-sensitive AEAD and hash benchmark groups.  Criterion saves the
#   run under a baseline named after the host machine architecture
#   (`uname -m`), e.g. `arch-aarch64` on Apple Silicon / ARM servers, so that
#   baselines gathered on different machines never overwrite one another.
#
#   The intent is to compare the two dominant symmetric-crypto ISA families:
#
#     * aarch64 / NEON  — the ARM Advanced SIMD path (Crypto Extensions for AES).
#     * x86_64  / AES-NI — the Intel/AMD AES-NI + AVX2 + SHA-NI path.
#
#   ── Scope / honest deferral ────────────────────────────────────────────────
#   This script profiles ONLY the architecture it is *run on*.  Running it on an
#   aarch64 host (e.g. Apple Silicon) records the NEON baseline natively.  The
#   x86_64 (AES-NI) leg must be recorded by running this same script on an
#   x86_64 host or via CI cross-compilation + hardware/emulation — it is
#   intentionally NOT faked here.  To combine both legs, run this script once on
#   each architecture with `--archive`, then diff the two archived
#   `arch-<arch>` baselines under target/bench_archive/.
#
# Requirements:
#   - cargo (Rust toolchain in PATH)
#   - uname (standard Unix tool)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$BENCH_DIR/../.." && pwd)"

DO_ARCHIVE=0
VERSION=""
SHOW_HELP=0
BENCHES=()

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --archive)
            DO_ARCHIVE=1
            shift
            ;;
        --version)
            VERSION="${2:-}"
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
            BENCHES+=("$1")
            shift
            ;;
    esac
done

if [[ "$SHOW_HELP" -eq 1 ]]; then
    sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

if [[ "${#BENCHES[@]}" -eq 0 ]]; then
    BENCHES=(aead hash)
fi

ARCH="$(uname -m 2>/dev/null || echo unknown)"
BASELINE="arch-${ARCH}"
UNAME_FULL="$(uname -srm 2>/dev/null || echo unknown)"

echo "── OxiCrypto native-architecture benchmark profile ──────────────────────"
echo "  Host architecture : ${ARCH}"
echo "  Platform          : ${UNAME_FULL}"
echo "  Criterion baseline: ${BASELINE}"
echo "  Benchmark groups  : ${BENCHES[*]}"
echo

case "$ARCH" in
    aarch64|arm64)
        echo "  ISA note: recording the ARM NEON / Crypto-Extensions baseline natively."
        ;;
    x86_64|amd64)
        echo "  ISA note: recording the x86_64 AES-NI / AVX2 / SHA-NI baseline natively."
        ;;
    *)
        echo "  ISA note: unrecognized architecture — baseline recorded verbatim."
        ;;
esac
echo

# ── Run the benchmarks, saving a per-architecture baseline ────────────────────

for bench in "${BENCHES[@]}"; do
    echo "→ cargo bench -p oxicrypto-bench --bench ${bench} -- --save-baseline ${BASELINE}"
    ( cd "$WORKSPACE_DIR" && \
      cargo bench -p oxicrypto-bench --bench "${bench}" -- --save-baseline "${BASELINE}" )
done

echo
echo "Native ${ARCH} baseline saved as '${BASELINE}'."
echo "The complementary architecture (see script header) must be profiled on its"
echo "own host / CI runner — this run does not synthesize cross-architecture numbers."

# ── Optional: archive with a per-arch version label ───────────────────────────

if [[ "$DO_ARCHIVE" -eq 1 ]]; then
    ARCHIVE_ARGS=()
    if [[ -n "$VERSION" ]]; then
        ARCHIVE_ARGS+=(--version "${VERSION}-${ARCH}")
    fi
    echo
    echo "→ Archiving results (label suffix: ${ARCH})"
    "${SCRIPT_DIR}/bench_archive.sh" "${ARCHIVE_ARGS[@]}"
fi
