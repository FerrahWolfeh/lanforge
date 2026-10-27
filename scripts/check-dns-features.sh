#!/usr/bin/env bash
# Builds and tests lanforge-dns under each feature set a slim build may pick.
# Every TLS-using feature needs a crypto provider (`ring` or `aws-lc`).
set -euo pipefail

# Each feature set is a fresh build: incremental caches only fill the target dir.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

FEATURE_SETS=(
    ""
    "ring"
    "adblock,ring"
    "dot,ring"
    "doq,ring"
    "doh-upstream,ring"
    "adblock,dot,doq,doh-upstream,aws-lc"
)

for features in "${FEATURE_SETS[@]}"; do
    echo "==> lanforge-dns [${features:-no features}]"
    RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-dns --no-default-features \
        ${features:+--features "$features"} --quiet
done

# The TLS loader shared by DoT, DoQ and HTTPS lives in lanforge-crypto.
for features in "" "tls,ring" "tls,aws-lc"; do
    echo "==> lanforge-crypto [${features:-no features}]"
    RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-crypto --no-default-features \
        ${features:+--features "$features"} --quiet
done
