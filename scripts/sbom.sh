#!/usr/bin/env bash
# Generate CycloneDX SBOMs for the whole repo (Cargo workspace + frontend
# npm deps in one pass each) with two independent generators, then score
# both for quality. Two generators, not one, because they don't always
# agree on component depth/licensing metadata — running both and diffing
# their sbomqs scores catches gaps neither one alone would surface.
#
# Usage: scripts/sbom.sh
# Output: sbom/syft.cdx.json, sbom/cdxgen.cdx.json, sbom/*.quality.{txt,json}
#
# Tool versions are pinned deliberately (not "latest") so a run today and a
# run in six months produce comparable output. Bump them here on purpose.
set -euo pipefail

SYFT_VERSION="1.50.0"
SBOMQS_VERSION="2.0.11"
CDXGEN_VERSION="12.8.2"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="$ROOT_DIR/.sbom-tools"
OUT_DIR="$ROOT_DIR/sbom"
mkdir -p "$TOOLS_DIR" "$OUT_DIR"

# ── Platform detection ───────────────────────────────────────────────────────
uname_s="$(uname -s)"
uname_m="$(uname -m)"

case "$uname_s" in
  Linux*)                OS=linux ;;
  Darwin*)                OS=darwin ;;
  MINGW*|MSYS*|CYGWIN*)   OS=windows ;;
  *) echo "sbom.sh: unsupported OS '$uname_s'" >&2; exit 1 ;;
esac

case "$uname_m" in
  x86_64|amd64)   ARCH=amd64 ;;
  arm64|aarch64)  ARCH=arm64 ;;
  *) echo "sbom.sh: unsupported arch '$uname_m'" >&2; exit 1 ;;
esac

BIN_EXT=""
[ "$OS" = "windows" ] && BIN_EXT=".exe"

# ── Ensure syft ───────────────────────────────────────────────────────────────
SYFT_BIN="$TOOLS_DIR/syft-${SYFT_VERSION}${BIN_EXT}"
if [ ! -x "$SYFT_BIN" ]; then
  echo "sbom.sh: installing syft v${SYFT_VERSION} (${OS}/${ARCH})..."
  archive_ext="tar.gz"
  [ "$OS" = "windows" ] && archive_ext="zip"
  url="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${OS}_${ARCH}.${archive_ext}"
  tmp="$(mktemp -d)"
  curl -sSfL "$url" -o "$tmp/syft.${archive_ext}"
  if [ "$archive_ext" = "zip" ]; then
    unzip -q "$tmp/syft.${archive_ext}" -d "$tmp"
  else
    tar -xzf "$tmp/syft.${archive_ext}" -C "$tmp"
  fi
  mv "$tmp/syft${BIN_EXT}" "$SYFT_BIN"
  chmod +x "$SYFT_BIN"
  rm -rf "$tmp"
fi

# ── Ensure sbomqs ─────────────────────────────────────────────────────────────
SBOMQS_BIN="$TOOLS_DIR/sbomqs-${SBOMQS_VERSION}${BIN_EXT}"
if [ ! -x "$SBOMQS_BIN" ]; then
  echo "sbom.sh: installing sbomqs v${SBOMQS_VERSION} (${OS}/${ARCH})..."
  case "$OS" in
    linux)   sq_os="Linux" ;;
    darwin)  sq_os="Darwin" ;;
    windows) sq_os="Windows" ;;
  esac
  sq_arch="x86_64"
  [ "$ARCH" = "arm64" ] && sq_arch="arm64"
  url="https://github.com/interlynk-io/sbomqs/releases/download/v${SBOMQS_VERSION}/sbomqs_${SBOMQS_VERSION}_${sq_os}_${sq_arch}.tar.gz"
  tmp="$(mktemp -d)"
  curl -sSfL "$url" -o "$tmp/sbomqs.tar.gz"
  tar -xzf "$tmp/sbomqs.tar.gz" -C "$tmp"
  mv "$tmp/sbomqs${BIN_EXT}" "$SBOMQS_BIN"
  chmod +x "$SBOMQS_BIN"
  rm -rf "$tmp"
fi

# ── Generate ──────────────────────────────────────────────────────────────────
# Excludes matter here, not just for speed: target/ and node_modules/ are
# build output and vendored trees Cargo.lock/package-lock.json already
# describe — walking them too adds nothing but a syft scan that's an order
# of magnitude slower (target/ alone can be 50k+ files on a workspace this
# size) and risks the cataloger picking up build artifacts as if they were
# first-party components.
EXCLUDE_GLOBS=(
  "./target/**"
  "./frontend/node_modules/**"
  "./frontend/.next/**"
  "./frontend/.turbo/**"
  "./.git/**"
  "./.sbom-tools/**"
  "./sbom/**"
)

echo "sbom.sh: generating sbom/syft.cdx.json..."
# --enrich all: fills in license data Syft's javascript cataloger doesn't
# already pull from package-lock.json (npm lockfiles don't always embed
# a "license" field per package — some need an npm-registry lookup).
# Does NOT touch cargo: Syft has no rust/cargo enrichment source (its
# --help only lists all|golang|java|javascript|python|vcpkg), and Cargo.lock
# itself never carries license data — see the note above sbomqs scoring
# below for why the cargo-side licensing gap needs a different tool
# entirely, not a flag.
syft_excludes=()
for g in "${EXCLUDE_GLOBS[@]}"; do syft_excludes+=(--exclude "$g"); done
( cd "$ROOT_DIR" && "$SYFT_BIN" . "${syft_excludes[@]}" --enrich all -o "cyclonedx-json=$OUT_DIR/syft.cdx.json" )

echo "sbom.sh: generating sbom/cdxgen.cdx.json..."
# cdxgen already ignores node_modules/.git/target by default; the explicit
# excludes here are just belt-and-suspenders for the same reason as above.
# --profile license-compliance: prioritizes license resolution over the
# default generic profile. --license-ref: synthesizes a LicenseRef- id for
# any component cdxgen still can't resolve a real license for, instead of
# leaving the field empty — same caveat as above, this makes every
# component *carry* a license field, not necessarily the *correct* one for
# ecosystems (cargo) neither tool can look up license data for locally.
cdxgen_excludes=()
for g in "${EXCLUDE_GLOBS[@]}"; do cdxgen_excludes+=(--exclude "$g"); done
( cd "$ROOT_DIR" && npx --yes "@cyclonedx/cdxgen@${CDXGEN_VERSION}" -r "${cdxgen_excludes[@]}" \
    --profile license-compliance --license-ref -o "$OUT_DIR/cdxgen.cdx.json" . )

# ── Score ─────────────────────────────────────────────────────────────────────
echo
echo "── syft SBOM quality ──"
"$SBOMQS_BIN" score "$OUT_DIR/syft.cdx.json" | tee "$OUT_DIR/syft.quality.txt"
"$SBOMQS_BIN" score "$OUT_DIR/syft.cdx.json" --json > "$OUT_DIR/syft.quality.json"

echo
echo "── cdxgen SBOM quality ──"
"$SBOMQS_BIN" score "$OUT_DIR/cdxgen.cdx.json" | tee "$OUT_DIR/cdxgen.quality.txt"
"$SBOMQS_BIN" score "$OUT_DIR/cdxgen.cdx.json" --json > "$OUT_DIR/cdxgen.quality.json"

echo
echo "sbom.sh: done — SBOMs and quality reports in $OUT_DIR/"
