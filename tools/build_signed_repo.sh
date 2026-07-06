#!/bin/sh

set -eu

usage()
{
    cat <<'EOF'
Usage:
  tools/build_signed_repo.sh --packages DIR --private-key KEY --output DIR [--abi ABI] [--channel CHANNEL]

Creates a FreeBSD/pkg repository directory for PondSec NDR packages, signs the
pkg catalogue with the provided private key, and writes SHA-256 checksums.

The script must run on a system with pkg(8). Keep the private key offline or
inside a locked release builder; never commit it to Git.
EOF
}

PACKAGES_DIR=
PRIVATE_KEY=
OUTPUT_DIR=
ABI=${ABI:-}
CHANNEL=${CHANNEL:-latest}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --packages)
            PACKAGES_DIR=${2:-}
            shift 2
            ;;
        --private-key)
            PRIVATE_KEY=${2:-}
            shift 2
            ;;
        --output)
            OUTPUT_DIR=${2:-}
            shift 2
            ;;
        --abi)
            ABI=${2:-}
            shift 2
            ;;
        --channel)
            CHANNEL=${2:-}
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

if [ -z "$PACKAGES_DIR" ] || [ -z "$PRIVATE_KEY" ] || [ -z "$OUTPUT_DIR" ]; then
    usage >&2
    exit 64
fi

if [ ! -d "$PACKAGES_DIR" ]; then
    echo "Package directory not found: $PACKAGES_DIR" >&2
    exit 66
fi

if [ ! -f "$PRIVATE_KEY" ]; then
    echo "Signing key not found: $PRIVATE_KEY" >&2
    exit 66
fi

if ! command -v pkg >/dev/null 2>&1; then
    echo "pkg(8) is required to create a FreeBSD package repository." >&2
    exit 69
fi

if [ -z "$ABI" ]; then
    ABI=$(pkg config ABI 2>/dev/null || true)
fi

if [ -z "$ABI" ]; then
    echo "Unable to determine ABI. Pass --abi FreeBSD:14:amd64 or similar." >&2
    exit 69
fi

REPO_DIR="${OUTPUT_DIR%/}/${ABI}/${CHANNEL}"
mkdir -p "$REPO_DIR"

rm -f \
    "$REPO_DIR"/os-pondsec-ndr-*.txz \
    "$REPO_DIR"/repo.* \
    "$REPO_DIR"/packagesite.* \
    "$REPO_DIR"/meta.* \
    "$REPO_DIR"/digests.* \
    "$REPO_DIR"/SHA256SUMS

found_package=0
for pkg_file in "$PACKAGES_DIR"/os-pondsec-ndr-*.txz; do
    [ -e "$pkg_file" ] || continue
    cp -p "$pkg_file" "$REPO_DIR/"
    found_package=1
done

if [ "$found_package" -ne 1 ]; then
    echo "No os-pondsec-ndr-*.txz package found in $PACKAGES_DIR" >&2
    exit 66
fi

pkg repo "$REPO_DIR" "$PRIVATE_KEY"

(
    cd "$REPO_DIR"
    : > SHA256SUMS
    if command -v sha256 >/dev/null 2>&1; then
        for checksum_file in os-pondsec-ndr-*.txz repo.* packagesite.* meta.* digests.*; do
            [ -e "$checksum_file" ] || continue
            sha256 "$checksum_file" >> SHA256SUMS
        done
    elif command -v sha256sum >/dev/null 2>&1; then
        for checksum_file in os-pondsec-ndr-*.txz repo.* packagesite.* meta.* digests.*; do
            [ -e "$checksum_file" ] || continue
            sha256sum "$checksum_file" >> SHA256SUMS
        done
    else
        for checksum_file in os-pondsec-ndr-*.txz repo.* packagesite.* meta.* digests.*; do
            [ -e "$checksum_file" ] || continue
            shasum -a 256 "$checksum_file" >> SHA256SUMS
        done
    fi
)

cat <<EOF
PondSec NDR repository created:
  Repository: $REPO_DIR
  ABI:        $ABI
  Channel:    $CHANNEL
  Checksums:  $REPO_DIR/SHA256SUMS

Publish the repository directory over HTTPS and distribute only the public key
to clients.
EOF
