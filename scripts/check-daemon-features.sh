#!/usr/bin/env bash
# Builds the daemon (`lanforge`) under each feature set a slim build may pick: every service
# alone, the profiles, and no services at all. A missing `#[cfg]` shows up here, never in the
# default build. TLS users (HTTP, DoT/DoQ) need a crypto provider (`ring` or `aws-lc`).
set -euo pipefail

# Each feature set is a fresh build: incremental caches only fill the target dir.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

FEATURE_SETS=(
    ""
    "dhcp"
    "dns"
    "ra"
    "tftp"
    "pppoe"
    "nft"
    "traffic"
    "discovery"
    "http,ring"
    "uds"
    "profile-minimal"
    "profile-soho"
    "profile-enterprise"
    "full"
)

# Tests run on the slimmest set and the smallest real profile; the default build runs them in
# the normal `cargo test`. The sets in between only need to type-check every target.
TEST_SETS=("" "profile-minimal")

for features in "${FEATURE_SETS[@]}"; do
    action=check
    for t in "${TEST_SETS[@]}"; do
        [[ "$features" == "$t" ]] && action=test
    done
    echo "==> lanforge [${features:-no features}] ($action)"
    if [[ $action == test ]]; then
        RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge --no-default-features \
            ${features:+--features "$features"} --quiet
    else
        RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo check -p lanforge --no-default-features \
            ${features:+--features "$features"} --all-targets --quiet
    fi
done
