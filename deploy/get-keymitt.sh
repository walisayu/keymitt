#!/bin/sh
# One-line keymitt install for macOS and Linux: detect the platform, download the
# matching release, verify its SHA-256 checksum, and install the binary.
#
#   curl -fsSL https://keymitt.walisayu.com/install.sh | sh
#   curl -fsSL https://keymitt.walisayu.com/install.sh | sh -s -- --version v0.1.0
#
# POSIX sh only: /bin/sh is dash on Debian and busybox ash on Alpine, so no bash syntax.
# The website serves a copy of this file; edit it here, in the keymitt repository.
#
# Everything runs inside main(), called on the very last line, so a download that is cut
# short executes nothing instead of half a script.
set -eu

usage() {
    cat <<'USAGE'
keymitt installer

  --version <tag>        Version to install, e.g. v0.1.0 (default: the latest release)
  --bin-dir <dir>        Where to put the keymitt binary
                         (default: ~/.local/bin, or /usr/local/bin when run as root)
  --repo <owner/name>    Download from another GitHub repository
  --base-url <url>       Download from this location instead of GitHub Releases
                         (it must contain the archive and SHA256SUMS.txt)
  --allow-insecure-http  Allow a plain-HTTP --base-url (trusted local networks only)
  -h, --help             Show this help

Environment: KEYMITT_VERSION, KEYMITT_INSTALL_DIR, KEYMITT_REPO, KEYMITT_BASE_URL
USAGE
}

say() { printf '%s\n' "$*"; }
die() { printf 'keymitt install: %s\n' "$*" >&2; exit 1; }

# fetch <url> <file>: HTTPS only, unless --allow-insecure-http was given.
fetch() {
    case "$1" in
        https://*) ;;
        http://*)
            [ "${ALLOW_INSECURE_HTTP}" = 1 ] ||
                die "refusing to download over plain HTTP: $1 (see --allow-insecure-http)" ;;
        *) die "unsupported URL: $1" ;;
    esac
    if [ "${DOWNLOADER}" = curl ]; then
        if [ "${ALLOW_INSECURE_HTTP}" = 1 ]; then proto='=http,https'; else proto='=https'; fi
        curl -fsSL --proto "${proto}" --proto-redir "${proto}" --retry 3 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

main() {
    REPO="${KEYMITT_REPO:-walisayu/keymitt}"
    VERSION="${KEYMITT_VERSION:-latest}"
    BASE_URL="${KEYMITT_BASE_URL:-}"
    BIN_DIR="${KEYMITT_INSTALL_DIR:-}"
    ALLOW_INSECURE_HTTP=0

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version) VERSION="${2:-}"; shift 2 ;;
            --bin-dir) BIN_DIR="${2:-}"; shift 2 ;;
            --repo) REPO="${2:-}"; shift 2 ;;
            --base-url) BASE_URL="${2:-}"; shift 2 ;;
            --allow-insecure-http) ALLOW_INSECURE_HTTP=1; shift ;;
            -h|--help) usage; exit 0 ;;
            *) usage >&2; die "unknown option: $1" ;;
        esac
    done

    case "${REPO}" in
        */*) ;;
        *) die "--repo must look like owner/name" ;;
    esac
    case "${REPO}" in
        *[!A-Za-z0-9._/-]*) die "--repo contains unexpected characters" ;;
    esac

    if command -v curl >/dev/null 2>&1; then
        DOWNLOADER=curl
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOADER=wget
    else
        die "curl or wget is required"
    fi

    # --- Platform ---------------------------------------------------------------
    case "$(uname -s)" in
        Darwin) OS="apple-darwin" ;;
        Linux) OS="unknown-linux-musl" ;;
        MINGW* | MSYS* | CYGWIN*)
            die "on Windows, run this in PowerShell instead: irm https://keymitt.walisayu.com/install.ps1 | iex" ;;
        *) die "unsupported operating system: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) ARCH="x86_64" ;;
        arm64 | aarch64) ARCH="aarch64" ;;
        *) die "unsupported CPU architecture: $(uname -m)" ;;
    esac
    # A shell running under Rosetta reports x86_64 on Apple silicon; install the native build.
    if [ "${OS}" = apple-darwin ] && [ "${ARCH}" = x86_64 ] &&
        [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
        ARCH="aarch64"
    fi
    TARGET="${ARCH}-${OS}"

    WORK="$(mktemp -d 2>/dev/null || mktemp -d -t keymitt)"
    trap 'rm -rf "${WORK}"' EXIT INT TERM

    # --- Version ----------------------------------------------------------------
    if [ "${VERSION}" = latest ]; then
        [ -z "${BASE_URL}" ] || die "--base-url needs an explicit --version"
        fetch "https://api.github.com/repos/${REPO}/releases/latest" "${WORK}/latest.json" ||
            die "could not look up the latest release of ${REPO} (has one been published?)"
        VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${WORK}/latest.json" | head -n 1)"
        [ -n "${VERSION}" ] || die "could not read the latest release tag of ${REPO}"
    fi
    case "${VERSION}" in
        v*) ;;
        *) VERSION="v${VERSION}" ;;
    esac
    case "${VERSION}" in
        *[!A-Za-z0-9._-]*) die "invalid version: ${VERSION}" ;;
    esac
    [ -n "${BASE_URL}" ] || BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    BASE_URL="${BASE_URL%/}"

    NAME="keymitt-${VERSION}-${TARGET}"
    ARCHIVE="${NAME}.tar.gz"
    say "==> keymitt ${VERSION} (${TARGET})"

    # --- Download and verify ----------------------------------------------------
    fetch "${BASE_URL}/${ARCHIVE}" "${WORK}/${ARCHIVE}" || die "download failed: ${BASE_URL}/${ARCHIVE}"
    fetch "${BASE_URL}/SHA256SUMS.txt" "${WORK}/SHA256SUMS.txt" || die "download failed: ${BASE_URL}/SHA256SUMS.txt"

    EXPECTED="$(awk -v a="${ARCHIVE}" '$2 == a || $2 == "*" a { print $1; exit }' "${WORK}/SHA256SUMS.txt")"
    [ -n "${EXPECTED}" ] || die "SHA256SUMS.txt has no entry for ${ARCHIVE}"
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL="$(sha256sum "${WORK}/${ARCHIVE}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL="$(shasum -a 256 "${WORK}/${ARCHIVE}" | awk '{print $1}')"
    else
        die "sha256sum or shasum is required to verify the download"
    fi
    [ "${EXPECTED}" = "${ACTUAL}" ] || die "checksum mismatch for ${ARCHIVE}; refusing to install"
    say "==> checksum verified"

    # --- Extract ------------------------------------------------------------------
    # Every entry must live under ${NAME}/ with no '..' component; then take only the binary.
    tar -tzf "${WORK}/${ARCHIVE}" > "${WORK}/listing" || die "the archive is not a valid tar.gz"
    while IFS= read -r entry; do
        case "${entry}" in
            "${NAME}" | "${NAME}/" | "${NAME}/"*) ;;
            *) die "unexpected entry in the archive: ${entry}" ;;
        esac
        case "/${entry}/" in
            */../*) die "unsafe path in the archive: ${entry}" ;;
        esac
    done < "${WORK}/listing"
    mkdir "${WORK}/x"
    tar -xzf "${WORK}/${ARCHIVE}" -C "${WORK}/x" "${NAME}/keymitt" || die "the archive does not contain ${NAME}/keymitt"
    BINARY="${WORK}/x/${NAME}/keymitt"
    [ -f "${BINARY}" ] && [ ! -L "${BINARY}" ] || die "the archive's keymitt is not a regular file"

    # --- Install -----------------------------------------------------------------
    if [ -z "${BIN_DIR}" ]; then
        if [ "$(id -u)" = 0 ]; then
            BIN_DIR="/usr/local/bin"
        else
            BIN_DIR="${HOME}/.local/bin"
        fi
    fi
    mkdir -p "${BIN_DIR}" || die "cannot create ${BIN_DIR} (try --bin-dir)"
    TMP_BIN="$(mktemp "${BIN_DIR}/.keymitt.XXXXXX")" || die "cannot write to ${BIN_DIR} (try --bin-dir)"
    cp "${BINARY}" "${TMP_BIN}" || die "cannot write to ${BIN_DIR} (try --bin-dir)"
    chmod 755 "${TMP_BIN}"
    mv -f "${TMP_BIN}" "${BIN_DIR}/keymitt"
    INSTALLED="$("${BIN_DIR}/keymitt" --version 2>/dev/null)" || die "installed ${BIN_DIR}/keymitt, but it does not run"
    say "==> installed ${INSTALLED} to ${BIN_DIR}/keymitt"

    case ":${PATH}:" in
        *":${BIN_DIR}:"*) ;;
        *)
            case "$(basename "${SHELL:-sh}")" in
                zsh) RC="~/.zprofile" ;;
                bash) RC="~/.bashrc" ;;
                *) RC="your shell's startup file" ;;
            esac
            say ""
            say "${BIN_DIR} is not on your PATH. Add this line to ${RC}:"
            say "  export PATH=\"${BIN_DIR}:\$PATH\""
            ;;
    esac

    say ""
    say "Next steps:"
    say "  Check the keychain and the approval prompt:"
    say "    keymitt doctor --approval"
    say "  Store a secret:"
    say "    keymitt add <name> --host <api-host>"
    say "  Connect Claude Code:"
    say "    keymitt setup claude"
    say "Docs: https://keymitt.walisayu.com/guide/getting-started"
}

main "$@"
