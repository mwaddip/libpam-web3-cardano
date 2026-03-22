#!/bin/bash
#
# Build a .deb package for libpam-web3-cardano
#
# This package contains:
#   - Cardano verification plugin for PAM
#   - web3-auth-svc (Cardano CIP-30 signing server)
#   - Signing page HTML + engine.js
#   - Systemd unit and tmpfiles.d config
#
# Usage: ./packaging/build-deb.sh
#
# Requirements:
#   - cargo (Rust toolchain)
#   - node + npx (for esbuild bundling of auth-svc)
#   - dpkg-deb

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VERSION="0.1.0"
ARCH="amd64"
PKG_NAME="libpam-web3-cardano"
PKG_DIR="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}"

echo "=== Building ${PKG_NAME} ${VERSION} for ${ARCH} ==="

# Clean previous build
rm -rf "$PKG_DIR"
rm -f "$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

# 1. Build Rust plugin binary
echo "[1/4] Building Cardano verification plugin..."
cd "$PROJECT_DIR"
cargo build --release

# 2. Bundle auth-svc with esbuild
echo "[2/4] Bundling auth-svc..."
cd "$PROJECT_DIR"
if ! command -v npx &> /dev/null; then
    echo "ERROR: npx not found. Install Node.js to bundle auth-svc."
    exit 1
fi

# Install build dependencies
npm install --save-dev esbuild 2>/dev/null
npm install cbor @noble/ed25519 @noble/curves @noble/hashes 2>/dev/null

npx esbuild auth-svc-src/index.ts \
    --bundle --platform=node --target=node22 --minify \
    --outfile=auth-svc.js

# 3. Create package directory structure
echo "[3/4] Creating package structure..."
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/lib/libpam-web3/plugins"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/blockhost/auth-svc/cardano"
mkdir -p "$PKG_DIR/usr/share/blockhost/signing-pages/cardano"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/lib/tmpfiles.d"
mkdir -p "$PKG_DIR/usr/share/doc/${PKG_NAME}"

# Copy plugin binary
cp "$PROJECT_DIR/target/release/cardano" "$PKG_DIR/usr/lib/libpam-web3/plugins/"

# Copy bundled auth-svc
cp "$PROJECT_DIR/auth-svc.js" "$PKG_DIR/usr/share/blockhost/auth-svc/cardano/"

# Create wrapper script for auth-svc
cat > "$PKG_DIR/usr/bin/web3-auth-svc-cardano" << 'WRAPPER'
#!/bin/sh
exec node /usr/share/blockhost/auth-svc/cardano/auth-svc.js "$@"
WRAPPER

# Copy signing page (served directly by auth-svc)
cp "$PROJECT_DIR/signing-page/index.html" "$PKG_DIR/usr/share/blockhost/signing-pages/cardano/"
cp "$PROJECT_DIR/signing-page/engine.js" "$PKG_DIR/usr/share/blockhost/signing-pages/cardano/"

# Copy systemd unit
cp "$PROJECT_DIR/web3-auth-svc.service" "$PKG_DIR/lib/systemd/system/web3-auth-svc-cardano.service"

# Copy tmpfiles.d config
cp "$PROJECT_DIR/libpam-web3.conf" "$PKG_DIR/usr/lib/tmpfiles.d/"

# Copy config example as documentation
cp "$PROJECT_DIR/config.example.toml" "$PKG_DIR/usr/share/doc/${PKG_NAME}/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Depends: libpam-web3, nodejs (>= 18)
Maintainer: libpam-web3 maintainers
Homepage: https://github.com/mwaddip/libpam-web3-cardano
Description: Cardano authentication plugin for libpam-web3
 Adds Cardano CIP-30 wallet authentication support to libpam-web3.
 .
 Components:
  - Verification plugin (Ed25519 key → Cardano address derivation)
  - web3-auth-svc (HTTPS signing server with COSE_Sign1 verification)
  - Signing page (CIP-30 compatible wallet UI)
 .
 Requires libpam-web3 (core PAM module) to be installed.
EOF

# Create postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    configure)
        systemd-tmpfiles --create /usr/lib/tmpfiles.d/libpam-web3.conf 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable --now web3-auth-svc-cardano 2>/dev/null || true
        echo ""
        echo "=== libpam-web3-cardano installed ==="
        echo ""
        echo "Plugin:       /usr/lib/libpam-web3/plugins/cardano"
        echo "Auth-svc:     systemctl status web3-auth-svc-cardano"
        echo "Signing page: https://\$(hostname):34206/"
        echo ""
        echo "No configuration needed — port derived from chain name, TLS from libpam-web3."
        echo ""
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Create prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    remove|upgrade)
        systemctl stop web3-auth-svc-cardano 2>/dev/null || true
        systemctl disable web3-auth-svc-cardano 2>/dev/null || true
        ;;
esac
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Set permissions
find "$PKG_DIR" -type d -exec chmod 755 {} \;
find "$PKG_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 755 "$PKG_DIR/DEBIAN/prerm"
chmod 755 "$PKG_DIR/usr/lib/libpam-web3/plugins/cardano"
chmod 755 "$PKG_DIR/usr/bin/web3-auth-svc-cardano"

# 4. Build the package
echo "[4/4] Building .deb package..."
cd "$SCRIPT_DIR"
dpkg-deb --build --root-owner-group "$PKG_DIR"

DEB_FILE="$SCRIPT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
if [ -f "$DEB_FILE" ]; then
    echo ""
    echo "=== Package built successfully ==="
    ls -lh "$DEB_FILE"
    echo ""
    dpkg-deb -c "$DEB_FILE"
else
    echo "ERROR: Package build failed"
    exit 1
fi
