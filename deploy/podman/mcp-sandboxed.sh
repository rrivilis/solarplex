#!/usr/bin/env bash
# Runs an MCP server implementation inside a rootless Podman container, as
# a process-isolation boundary for third-party/untrusted MCP server code.
#
# Integration point: sidecar spawns whatever UPSTREAM_MCP_CMD names via a
# plain shell invocation (see StdioUpstream::spawn in
# crates/sidecar/src/proxy.rs, called from proxy.rs::serve when
# config.upstream_mcp_cmd is set). Pointing UPSTREAM_MCP_CMD at this script
# instead of a bare MCP server binary sandboxes it — no Rust code changes
# needed, since the shell string sidecar runs was already fully general.
#
# Usage:
#   UPSTREAM_MCP_CMD="/path/to/mcp-sandboxed.sh <image> [bind-mount-dir]" \
#     cargo run -p sidecar
#
# The container talks MCP over stdio, same as an unsandboxed process would —
# `podman run -i` wires the container's stdin/stdout straight through.
#
# Env overrides:
#   MCP_SANDBOX_NETWORK        default "none". Most MCP servers don't need
#                               network access; set to e.g. "slirp4netns" for
#                               the ones that legitimately do (web-search,
#                               Slack, ...).
#   MCP_SANDBOX_MEMORY         default "256m".
#   MCP_SANDBOX_REQUIRE_SIGNED default "1" (enforced).
#
#                               Podman has no per-invocation --signature-
#                               policy flag on `run` or `pull` (checked
#                               against docs.podman.io's podman-run(1) and
#                               podman-pull(1) directly -- some third-party
#                               guides claim otherwise, they're wrong or
#                               describing a different tool). Verification is
#                               governed entirely by whichever policy.json is
#                               active for this account: first
#                               $XDG_CONFIG_HOME/containers/policy.json (or
#                               ~/.config/containers/policy.json), else
#                               /etc/containers/policy.json. So this script
#                               can't toggle enforcement per run the way it
#                               toggles --network/--memory -- what it *can*
#                               do is refuse to start at all if no policy
#                               file is in place, rather than silently
#                               running an unverified pull under whatever
#                               permissive default the host happens to have.
#
#                               ./policy.json (sibling to this script) is the
#                               fail-closed template: `"default": [{"type":
#                               "reject"}]`. Install it at one of the two
#                               paths above, then add a
#                               transports.docker."<registry>" entry
#                               (signedBy + a GPG keyPath, or sigstoreSigned
#                               + a keyPath) for each registry you actually
#                               trust -- see containers-policy.json(5).
#
#                               Set to "0" to skip this check and fall back
#                               to today's behavior (whatever the host's
#                               ambient policy.json says, often
#                               insecureAcceptAnything on a fresh install).
#                               Dev/test convenience, not for production --
#                               mirrors SOLARPLEX_ALLOW_UNSANDBOXED's role in
#                               crates/guardian/src/sandbox_entry.rs.

set -euo pipefail

if [ $# -lt 1 ]; then
	echo "usage: $0 <image> [bind-mount-dir]" >&2
	exit 1
fi

image="$1"
mount_dir="${2:-}"

network="${MCP_SANDBOX_NETWORK:-none}"
memory="${MCP_SANDBOX_MEMORY:-256m}"
require_signed="${MCP_SANDBOX_REQUIRE_SIGNED:-1}"

if [ "$require_signed" = "1" ]; then
	active_policy="${XDG_CONFIG_HOME:-$HOME/.config}/containers/policy.json"
	if [ ! -f "$active_policy" ]; then
		active_policy="/etc/containers/policy.json"
	fi
	if [ ! -f "$active_policy" ]; then
		script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
		echo "mcp-sandboxed.sh: no signature verification policy found (checked" >&2
		echo "  \${XDG_CONFIG_HOME:-\$HOME/.config}/containers/policy.json and" >&2
		echo "  /etc/containers/policy.json)." >&2
		echo "  Install $script_dir/policy.json at one of those paths, or set" >&2
		echo "  MCP_SANDBOX_REQUIRE_SIGNED=0 to run unverified (dev/test only)." >&2
		exit 1
	fi
fi

args=(
	run --rm -i
	--pull=missing
	--network="$network"
	--read-only
	--tmpfs /tmp:rw,size=64m
	--cap-drop=ALL
	--security-opt no-new-privileges
	--pids-limit=128
	--memory="$memory"
)

if [ -n "$mount_dir" ]; then
	args+=(--volume "$mount_dir:$mount_dir:rw")
fi

args+=("$image")

exec podman "${args[@]}"
