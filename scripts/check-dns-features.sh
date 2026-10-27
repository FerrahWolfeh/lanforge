#!/usr/bin/env bash
# Builds and tests lanforge-dns under each feature set a slim build may pick.
# Every TLS-using feature needs a crypto provider (`ring` or `aws-lc`).
set -euo pipefail

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
