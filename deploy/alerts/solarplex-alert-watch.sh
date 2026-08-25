#!/usr/bin/env bash
# Tails the solarplex.service journal and posts a webhook for every ERROR
# line, so an operator finds out about a failure without polling logs.
#
# Parses each line as JSON and checks its `.level` field, rather than
# filtering on journald's own priority field (`journalctl -p err`).
# journald's default priority comes from which *stream* a line arrived on
# (stdout = info, stderr = warning) — not from the line's actual content —
# and this codebase's tracing_subscriber writes everything to stdout.
# `-p err` would therefore silently never match a real tracing ERROR line.
# tracing_subscriber's `fmt::layer().json()` (crates/server/src/main.rs)
# emits one JSON object per line with a `level` field, which is what makes
# this a real parse instead of the brittle plain-text `grep ' ERROR '` this
# replaced — level detection no longer depends on the formatter's exact
# text layout (spacing, column order, timestamp format, ...) staying
# unchanged. Lines that fail to parse as JSON (a raw panic message printed
# directly to stderr, for instance — those never go through
# tracing_subscriber at all) are silently skipped here, same as they always
# were: this script only ever covered tracing-emitted ERROR events, not
# arbitrary stderr text.
#
# Requires: journalctl, curl, jq. Run as (or alongside) a user in the
# systemd-journal group — see solarplex-alerts.service.
#
# Configure via environment:
#   ALERT_WEBHOOK_URL   required. POSTed a JSON body: {"text": "<line>"}
#   SOLARPLEX_UNIT       optional, default "solarplex.service"

set -euo pipefail

: "${ALERT_WEBHOOK_URL:?ALERT_WEBHOOK_URL must be set}"
SOLARPLEX_UNIT="${SOLARPLEX_UNIT:-solarplex.service}"

journalctl -u "$SOLARPLEX_UNIT" -f -o cat --no-tail |
	while IFS= read -r line; do
		level=$(printf '%s' "$line" | jq -r '.level // empty' 2>/dev/null) || continue
		[ "$level" = "ERROR" ] || continue

		body=$(jq -n --arg text "[$SOLARPLEX_UNIT] $line" '{text: $text}')
		if ! curl -fsS -X POST -H 'Content-Type: application/json' \
			-d "$body" "$ALERT_WEBHOOK_URL" >/dev/null; then
			echo "solarplex-alert-watch: failed to deliver webhook for line: $line" >&2
		fi
	done
