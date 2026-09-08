#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=================================================="
echo " Lanforge RPM Package Builder for Fedora / dnf5   "
echo "=================================================="

# 1. Detect target directory (respects CARGO_TARGET_DIR if set, e.g. /mnt/ram/.rsbuild)
TARGET_DIR="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r .target_directory 2>/dev/null || echo "$REPO_ROOT/target")}"
echo "--> Cargo target directory: $TARGET_DIR"

# 2. Build release binaries
echo "--> Compiling binaries in release mode..."
cargo build --release --locked -p lanforge -p lanforge-cli -p lanforge-lab

# Verify binary artifacts
for bin in lanforged lanforge lanforge-lab; do
    if [ ! -f "$TARGET_DIR/release/$bin" ]; then
        echo "Error: Expected binary $TARGET_DIR/release/$bin not found!" >&2
        exit 1
    fi
done

# 3. Setup RPM build tree
RPM_TOPDIR="$REPO_ROOT/packaging/build/rpmbuild"
echo "--> Preparing RPM build root at: $RPM_TOPDIR"
rm -rf "$RPM_TOPDIR"
mkdir -p "$RPM_TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# 4. Stage sources and specs
cp "$REPO_ROOT/packaging/systemd/lanforge.service" "$RPM_TOPDIR/SOURCES/lanforge.service"
cp "$REPO_ROOT/packaging/sysusers/lanforge.conf" "$RPM_TOPDIR/SOURCES/lanforge.sysusers"
cp "$REPO_ROOT/packaging/tmpfiles/lanforge.conf" "$RPM_TOPDIR/SOURCES/lanforge.tmpfiles"
cp "$REPO_ROOT/contrib/lanforge.toml" "$RPM_TOPDIR/SOURCES/lanforge.toml"
cp "$REPO_ROOT/packaging/rpm/lanforge.spec" "$RPM_TOPDIR/SPECS/lanforge.spec"

# 5. Build binary RPM
echo "--> Executing rpmbuild..."
rpmbuild \
    --define "_topdir $RPM_TOPDIR" \
    --define "cargo_target_dir $TARGET_DIR" \
    --build-in-place \
    -bb "$RPM_TOPDIR/SPECS/lanforge.spec"

echo ""
echo "=================================================="
echo " Build successful! RPM packages generated:       "
echo "=================================================="
find "$RPM_TOPDIR/RPMS" -type f -name "*.rpm" -exec ls -lh {} +

echo ""
echo "To install on Fedora Server using dnf5:"
RPM_FILE=$(find "$RPM_TOPDIR/RPMS" -type f -name "*.rpm" | head -n 1)
echo "  sudo dnf5 install $RPM_FILE"
echo ""
echo "To manage services:"
echo "  sudo systemctl enable --now lanforge.service"
echo "  sudo usermod -aG lanforge \$USER   # grants CLI access without sudo"
echo "  lanforge status"
