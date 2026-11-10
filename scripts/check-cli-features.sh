#!/usr/bin/env bash
# Builds the admin CLI (`lanforge-cli`) under each feature set a build may pick. A missing
# `#[cfg(feature = "remote")]` shows up here, never in the default build. Every set needs a
# crypto provider (`ring` or `aws-lc`); `remote` adds the HTTP client and the saved login.
set -euo pipefail

# Each feature set is a fresh build: incremental caches only fill the target dir.
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

FEATURE_SETS=(
    "ring"
    "aws-lc"
    "remote,aws-lc"
)

# The default build (remote + ring) is covered by the normal clippy and test runs.
for features in "${FEATURE_SETS[@]}"; do
    echo "==> lanforge-cli [${features}]"
    RUSTFLAGS="${RUSTFLAGS:-} -D warnings" cargo test -p lanforge-cli --no-default-features \
        --features "$features" --quiet
done
