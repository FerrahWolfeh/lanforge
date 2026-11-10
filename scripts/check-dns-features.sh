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

# Tests (the lib and one integration binary per set) run on the two ends; the sets in between only need
# to type-check every target, which is where a missing gate shows up.
TEST_SETS=("" "adblock,dot,doq,doh-upstream,aws-lc")

for features in "${FEATURE_SETS[@]}"; do
    action=check
    for t in "${TEST_SETS[@]}"; do
        [[ "$features" == "$t" ]] && action=test
    done
    echo "==> lanforge-dns [${features:-no features}] ($action)"
    if [[ $action == test ]]; then
        RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-dns --no-default-features \
            ${features:+--features "$features"} --quiet
    else
        RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo check -p lanforge-dns --no-default-features \
            ${features:+--features "$features"} --all-targets --quiet
    fi
done

# The TLS loader shared by DoT, DoQ and HTTPS lives in lanforge-crypto.
for features in "" "tls,ring" "tls,aws-lc"; do
    echo "==> lanforge-crypto [${features:-no features}]"
    RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-crypto --no-default-features \
        ${features:+--features "$features"} --quiet
done

# Consumers built alongside lanforge-dns get its features through unification; each one
# must still compile with only the features it declares itself.
echo "==> lanforge-http with lanforge-dns (feature unification)"
RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo check -p lanforge-dns -p lanforge-http --all-targets --quiet
