#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if cargo tree --target x86_64-unknown-linux-gnu --edges normal 2>/dev/null | grep -E '(-sys v|ring v|aws-lc-rs v|openssl v)'; then
    echo "FFI LEAK DETECTED in oxicrypto"
    exit 1
fi
echo "oxicrypto FFI audit: CLEAN"
