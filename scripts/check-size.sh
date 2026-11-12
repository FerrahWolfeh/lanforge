#!/usr/bin/env bash
# Builds the release binaries and checks them against scripts/size-budget: fails when one grows
# more than SIZE_TOLERANCE_PCT (default 5) % over its budget. SKIP_BUILD=1 checks what is built.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUDGET_FILE="$ROOT/scripts/size-budget"
TOLERANCE="${SIZE_TOLERANCE_PCT:-5}"
BIN_DIR="${CARGO_TARGET_DIR:-$ROOT/target}/release"

if [ "${SKIP_BUILD:-0}" != 1 ]; then
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked -p lanforge -p lanforge-cli
fi

status=0
while read -r bin budget; do
    [[ -z "$bin" || "$bin" == \#* ]] && continue
    size=$(stat -c %s "$BIN_DIR/$bin")
    delta=$(awk -v s="$size" -v b="$budget" 'BEGIN { printf "%+.1f", (s - b) * 100 / b }')
    printf '%-10s %10d bytes, budget %10d (%s %%)\n' "$bin" "$size" "$budget" "$delta"
    if (( size * 100 > budget * (100 + TOLERANCE) )); then
        echo "  over budget by more than ${TOLERANCE} %: find what grew, or raise the budget in scripts/size-budget" >&2
        status=1
    elif (( size * 100 < budget * (100 - TOLERANCE) )); then
        echo "  shrank more than ${TOLERANCE} %: lower the budget in scripts/size-budget"
    fi
done < "$BUDGET_FILE"
exit "$status"
