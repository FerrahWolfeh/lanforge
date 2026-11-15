#!/usr/bin/env bash
# Builds the admin CLI (`lanforge-cli`) under each feature set a build may pick. A missing
# `#[cfg(feature = "remote")]` shows up here, never in the default build. `remote` adds the
# HTTP client and the saved login and needs a TLS crypto provider (`ring` or `aws-lc`); without
# `remote` the CLI only talks to the local socket and the providers do nothing.
set -euo pipefail

# Each feature set is a fresh build: incremental caches only fill the target dir.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

FEATURE_SETS=(
    ""
    "remote,aws-lc"
)

# The default build (remote + ring) is covered by the normal clippy and test runs.
for features in "${FEATURE_SETS[@]}"; do
    echo "==> lanforge-cli [${features:-no features}]"
    RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-cli --no-default-features \
        ${features:+--features "$features"} --quiet
done
