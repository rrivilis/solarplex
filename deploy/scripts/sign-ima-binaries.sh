#!/usr/bin/env bash
# Signs the three agent-execution binaries for IMA appraisal (the kernel-LSM
# layer of docs/threat-model.md §4.6, complementing dm-verity's block-device
# layer — see build-verity-image.sh). Writes a `security.ima` extended
# attribute containing an HMAC signature the kernel checks at `execve` time;
# a binary substituted after signing fails appraisal and the kernel refuses
# to exec it, independent of and in addition to the dm-verity check.
#
# The private signing key is the trust root for this layer: whoever holds
# it can make an attacker's binary appraise as genuine. It should live only
# on a dedicated signing host or an Ansible-controller-side Vault secret,
# never copied to the hosts that run the signed binaries — those hosts only
# ever need the *public* certificate, loaded into the kernel's `.ima`
# keyring, to verify signatures made elsewhere. Same handling discipline as
# solarplex_age_identity in bootstrap_identity.yml: Vault-encrypted at
# rest, plaintext only transiently in this process's environment, never
# logged, never written to disk unsealed.
#
# Usage:
#   IMA_SIGNING_KEY=/path/to/private_key.pem \
#   IMA_SIGNING_CERT=/path/to/cert.pem \
#     sign-ima-binaries.sh <shim-bin> <guardian-bin> <adapter-bin>
#
# Signs the three binaries in place. Requires: evmctl (ima-evm-utils).

set -euo pipefail

if [ $# -ne 3 ]; then
	echo "usage: IMA_SIGNING_KEY=... IMA_SIGNING_CERT=... $0 <shim-bin> <guardian-bin> <adapter-bin>" >&2
	exit 1
fi

if [ -z "${IMA_SIGNING_KEY:-}" ] || [ -z "${IMA_SIGNING_CERT:-}" ]; then
	echo "error: IMA_SIGNING_KEY and IMA_SIGNING_CERT must both be set" >&2
	exit 1
fi

if ! command -v evmctl >/dev/null 2>&1; then
	echo "error: required tool 'evmctl' not found on PATH (package: ima-evm-utils)" >&2
	exit 1
fi

for f in "$@"; do
	if [ ! -f "$f" ]; then
		echo "error: $f does not exist" >&2
		exit 1
	fi
	# evmctl 1.5's `ima_sign` has no `--cert` flag at all (confirmed against a
	# real install, not assumed from docs) -- IMA_SIGNING_CERT is used here
	# via --keyid-from-cert to make the signature's embedded keyid match the
	# public cert's Subject Key Identifier, so the kernel's .ima keyring
	# lookup at execve time finds the right key deterministically instead of
	# relying on evmctl's own keyid derivation from the private key agreeing
	# with the cert by coincidence.
	evmctl ima_sign --key "$IMA_SIGNING_KEY" --keyid-from-cert "$IMA_SIGNING_CERT" "$f"
	echo "signed: $f"
done

echo "done. Verify with: evmctl ima_verify --key <public-cert> <binary>"
