#!/usr/bin/env bash
# Builds the dm-verity-protected image for the three agent-execution
# binaries (solarplex-shim, solarplex-guardian, solarplex-adapter) — see
# docs/threat-model.md §4.6. A host-level attacker who can replace
# solarplex-guardian on disk inherits its full execution authority; putting
# these three binaries on a dm-verity block device means a modified binary
# produces a hash-tree mismatch (I/O error) instead of silently loading.
#
# Packages the three binaries into a read-only squashfs image, then runs
# `veritysetup format` to produce the hash tree and root hash. The root
# hash is the thing that actually has to be trusted out-of-band (baked into
# a signed manifest, a kernel command-line arg, or an Ansible Vault-held
# var) — anyone who can silently change the root hash the host trusts can
# just as easily point it at a malicious image, so treat it with the same
# handling discipline as the age identity in bootstrap_identity.yml.
#
# Usage:
#   build-verity-image.sh <output-dir> <shim-bin> <guardian-bin> <adapter-bin>
#
# Produces, in <output-dir>:
#   solarplex-agent.img        the squashfs data device (mount this read-only)
#   solarplex-agent.hash       the dm-verity hash tree
#   solarplex-agent.roothash   the root hash, hex, newline-terminated
#
# Requires: mksquashfs (squashfs-tools), veritysetup (cryptsetup).
#
# This script only builds artifacts on disk — it does not mount anything,
# touch IMA, or modify a running host. See the solarplex_binary_integrity
# Ansible role for how these artifacts get deployed.

set -euo pipefail

if [ $# -ne 4 ]; then
	echo "usage: $0 <output-dir> <shim-bin> <guardian-bin> <adapter-bin>" >&2
	exit 1
fi

out_dir="$1"
shim_bin="$2"
guardian_bin="$3"
adapter_bin="$4"

for f in "$shim_bin" "$guardian_bin" "$adapter_bin"; do
	if [ ! -f "$f" ]; then
		echo "error: $f does not exist" >&2
		exit 1
	fi
done

for tool in mksquashfs veritysetup; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "error: required tool '$tool' not found on PATH" >&2
		exit 1
	fi
done

mkdir -p "$out_dir"

stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT

# --preserve=xattr: plain `cp` silently drops extended attributes (confirmed
# against a real mksquashfs + veritysetup + mount round-trip, not assumed).
# These binaries are signed with sign-ima-binaries.sh BEFORE this script
# runs, and that signature lives entirely in the `security.ima` xattr --
# without this flag it never survives into the squashfs image at all, and
# the whole IMA-EVM layer silently does nothing even though signing itself
# reported success.
cp --preserve=mode,timestamps,xattr "$shim_bin" "$stage_dir/solarplex-shim"
cp --preserve=mode,timestamps,xattr "$guardian_bin" "$stage_dir/solarplex-guardian"
cp --preserve=mode,timestamps,xattr "$adapter_bin" "$stage_dir/solarplex-adapter"
chmod 0755 "$stage_dir"/solarplex-*

img="$out_dir/solarplex-agent.img"
hash_file="$out_dir/solarplex-agent.hash"
roothash_file="$out_dir/solarplex-agent.roothash"

rm -f "$img" "$hash_file"

# -noappend: fail rather than merge into a stale image left over from a
# previous run — this script should always produce a fresh, fully
# reproducible image from exactly the three inputs given.
mksquashfs "$stage_dir" "$img" -noappend -all-root -no-progress

# Hash device as a separate regular file; veritysetup operates on regular
# files directly (loop devices are not required for `format`).
: >"$hash_file"

veritysetup format "$img" "$hash_file" | tee "$out_dir/solarplex-agent.verity-format.log"

root_hash="$(grep -E '^Root hash:' "$out_dir/solarplex-agent.verity-format.log" | awk '{print $NF}')"
if [ -z "$root_hash" ]; then
	echo "error: could not parse root hash from veritysetup output" >&2
	exit 1
fi
printf '%s\n' "$root_hash" >"$roothash_file"

echo "built $img"
echo "root hash: $root_hash (also written to $roothash_file)"
