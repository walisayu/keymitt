#!/bin/sh
# Packages a release build for macOS or Linux, in the layout deploy/get-keymitt.sh expects:
#   <out-dir>/keymitt-<version>-<target>.tar.gz  containing  keymitt-<version>-<target>/keymitt
#
# Usage: deploy/package.sh <target> <version-tag> <out-dir>
#   e.g. deploy/package.sh aarch64-apple-darwin v0.1.0 dist
# Run from the repository root after `cargo build --release --target <target>`.
set -eu

[ "$#" -eq 3 ] || { echo "usage: $0 <target> <version-tag> <out-dir>" >&2; exit 2; }
TARGET="$1"
VERSION="$2"
OUT="$3"
NAME="keymitt-${VERSION}-${TARGET}"
BINARY="target/${TARGET}/release/keymitt"

[ -f "${BINARY}" ] || { echo "missing ${BINARY}; build it first" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir "${STAGE}/${NAME}"
cp "${BINARY}" README.md README.zh-TW.md LICENSE-MIT LICENSE-APACHE "${STAGE}/${NAME}/"
chmod 755 "${STAGE}/${NAME}/keymitt"
mkdir -p "${OUT}"
tar -C "${STAGE}" -czf "${OUT}/${NAME}.tar.gz" "${NAME}"
echo "${OUT}/${NAME}.tar.gz"
