#!/usr/bin/env bash
# bench_archive.sh — Archive Criterion benchmark results per release version.
#
# Usage:
#   scripts/bench_archive.sh [--version VERSION] [--archive-dir DIR]
#
# Options:
#   --version VERSION     Tag the archive with this version string.
#                         Default: read from `git describe --tags --abbrev=0`,
#                         falling back to the current branch name.
#   --archive-dir DIR     Store archives in this directory.
#                         Default: target/bench_archive
#   --run-bench           Run `cargo bench` before archiving (default: off).
#                         Without this flag, the script only archives existing
#                         Criterion output from target/criterion/.
#   --help                Show this help and exit.
#
# Workflow:
#   1. Run benchmarks: `cargo bench -p oxicrypto-bench`
#   2. Archive results: `scripts/bench_archive.sh --version 0.1.1`
#   3. Inspect history: `ls target/bench_archive/`
#   4. Compare two versions: diff the summary files.
#
# Archive format:
#   target/bench_archive/<version>/criterion/  — copy of target/criterion/ tree
#   target/bench_archive/<version>/summary.md  — Markdown summary table
#   target/bench_archive/<version>/ratios.md   — OxiCrypto/ring ratio table
#   target/bench_archive/<version>/meta.json   — metadata (date, rustc, version)
#
# Requirements:
#   - cargo (Rust toolchain in PATH)
#   - git (for version auto-detection)
#   - Python 3.6+ (for bench_summary.py and bench_ratios.py)
#   - rsync or cp (standard Unix tools)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_DIR="$(cd "$BENCH_DIR/../.." && pwd)"

ARCHIVE_DIR="${WORKSPACE_DIR}/target/bench_archive"
VERSION=""
RUN_BENCH=0
SHOW_HELP=0

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --archive-dir)
            ARCHIVE_DIR="$2"
            shift 2
            ;;
        --run-bench)
            RUN_BENCH=1
            shift
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
            echo "Unexpected argument: $1" >&2
            exit 1
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

# ── Auto-detect version ────────────────────────────────────────────────────────

if [[ -z "$VERSION" ]]; then
    # Try latest git tag.
    if command -v git &>/dev/null && git -C "$WORKSPACE_DIR" rev-parse --git-dir &>/dev/null; then
        TAG="$(git -C "$WORKSPACE_DIR" describe --tags --abbrev=0 2>/dev/null || true)"
        if [[ -n "$TAG" ]]; then
            VERSION="$TAG"
        else
            # Fall back to branch name.
            BRANCH="$(git -C "$WORKSPACE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
            VERSION="${BRANCH//\//-}"
        fi
    else
        VERSION="unknown"
    fi
    info "Auto-detected version: ${VERSION}"
fi

# ── Optionally run benchmarks ─────────────────────────────────────────────────

cd "$WORKSPACE_DIR"

if [[ $RUN_BENCH -eq 1 ]]; then
    info "Running benchmarks (this takes several minutes)..."
    cargo bench -p oxicrypto-bench
    ok "Benchmarks complete."
fi

# ── Check that criterion output exists ────────────────────────────────────────

CRITERION_SRC="${WORKSPACE_DIR}/target/criterion"

if [[ ! -d "$CRITERION_SRC" ]]; then
    err "Criterion output directory not found: ${CRITERION_SRC}"
    err "Run 'cargo bench -p oxicrypto-bench' first, or use --run-bench."
    exit 1
fi

# ── Create archive directory ──────────────────────────────────────────────────

DEST="${ARCHIVE_DIR}/${VERSION}"
mkdir -p "$DEST"

info "Archiving to: ${DEST}"

# Copy criterion output tree.
if command -v rsync &>/dev/null; then
    rsync -a --delete "${CRITERION_SRC}/" "${DEST}/criterion/"
else
    rm -rf "${DEST}/criterion"
    cp -r "${CRITERION_SRC}" "${DEST}/criterion"
fi
ok "Criterion output copied."

# ── Generate summary.md ────────────────────────────────────────────────────────

if command -v python3 &>/dev/null; then
    info "Generating Markdown summary..."
    python3 "${SCRIPT_DIR}/bench_summary.py" \
        --criterion-dir "${DEST}/criterion" \
        > "${DEST}/summary.md" 2>/dev/null \
        && ok "summary.md written." \
        || warn "bench_summary.py failed; summary.md may be empty."

    info "Generating ratio report..."
    python3 "${SCRIPT_DIR}/bench_ratios.py" \
        --criterion-dir "${DEST}/criterion" \
        > "${DEST}/ratios.md" 2>/dev/null \
        && ok "ratios.md written." \
        || warn "bench_ratios.py: no comparison data (run hash bench for ring comparisons)."
else
    warn "python3 not found — skipping Markdown summary and ratio report."
fi

# ── Write metadata ─────────────────────────────────────────────────────────────

RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unknown)"
COMMIT_HASH="$(git -C "$WORKSPACE_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
ARCHIVE_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date +%Y-%m-%dT%H:%M:%SZ)"
UNAME_OUT="$(uname -srm 2>/dev/null || echo unknown)"

cat > "${DEST}/meta.json" <<EOF
{
  "version": "${VERSION}",
  "date": "${ARCHIVE_DATE}",
  "rustc": "${RUSTC_VERSION}",
  "commit": "${COMMIT_HASH}",
  "platform": "${UNAME_OUT}"
}
EOF

ok "meta.json written."

# ── List archive contents ──────────────────────────────────────────────────────

info ""
ok "Archive complete: ${DEST}"
info "Contents:"
ls -lh "${DEST}/" | awk '{print "  " $0}'

info ""
info "Available archives:"
ls -d "${ARCHIVE_DIR}/"*/ 2>/dev/null | while read -r d; do
    VER="$(basename "$d")"
    META="$d/meta.json"
    if [[ -f "$META" ]]; then
        DATE="$(python3 -c "import json; d=json.load(open('$META')); print(d.get('date','?'))" 2>/dev/null || echo "?")"
        printf '  %-20s  %s\n' "$VER" "$DATE"
    else
        printf '  %s\n' "$VER"
    fi
done
