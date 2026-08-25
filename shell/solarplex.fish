# solarplex.fish — Fish shell adapter for Solarplex
#
# Tracks every shell command as a session event so the Solarplex UI shows
# a live shell timeline alongside agent actions and approvals.
#
# Installation:
#   cp shell/solarplex.fish ~/.config/fish/conf.d/solarplex.fish
#   sp session attach <id> --actor <you>
#   source (sp session env | psub)
#
# Requires Fish 3.4+ (fish_postexec status argument).
# Requires `sp` binary installed in PATH: cargo build -p cli && fish_add_path ...

# ─── Shell-kind signal ────────────────────────────────────────────────────────
#
# Lets `sp plumb run` (clicking an OSC-8 session/<id>/enter link) know which
# adapter is loaded, so it emits `source ~/.config/solarplex/session.fish`
# rather than guessing — see crates/cli/src/cmd/plumb.rs::detected_shell_kind.
set -gx SOLARPLEX_SHELL_KIND fish

# ─── Load persisted session config ───────────────────────────────────────────

function __sp_load_config
    # JSON config is read by `sp` itself; we source the fish companion file
    # written by `sp session attach` so env vars survive new terminals.
    set -l fish_cfg $HOME/.config/solarplex/session.fish
    if test -f $fish_cfg
        source $fish_cfg
    end
end

__sp_load_config

# ─── Full-command tracking opt-in ────────────────────────────────────────────
#
# By default Solarplex records only the argv[0] binary name for each command.
# This avoids accidentally logging credentials that appear in command arguments
# (e.g. `psql postgresql://user:password@host/db` or `mysql -pMySecret`).
#
# To opt in to full-command logging set this variable before attaching or at
# any time during a session:
#
#   set -gx SOLARPLEX_TRACK_COMMANDS 1     # enable for this shell
#   set -e SOLARPLEX_TRACK_COMMANDS        # disable
#
# Even when enabled a client-side credential seatbelt will suppress the full
# argv if it detects a known secret pattern (URL credentials, --password flags,
# inline env-var assignments like AWS_SECRET_ACCESS_KEY=xxx, GitHub/Anthropic/
# OpenAI token literals, etc.).  The event will be stored with redacted=true
# and the UI will show "[credential detected — argv suppressed]" instead of the
# command text.
#
# IMPORTANT: The seatbelt is a last-resort guard, not the primary defense.
# It cannot catch credentials stored in shell variables ($MY_TOKEN), heredoc
# content, process-substitution payloads, or base64-encoded secrets.
# Keeping SOLARPLEX_TRACK_COMMANDS unset (the default) is always safest.

# ─── Sensitive command patterns ───────────────────────────────────────────────
# Commands matching these patterns will be submitted as approval requests
# and blocked until a Solarplex supervisor grants or denies them.
# Override by setting $SOLARPLEX_GATE_PATTERNS (space-separated list).

if not set -q SOLARPLEX_GATE_PATTERNS
    set -g SOLARPLEX_GATE_PATTERNS \
        "rm -rf" \
        "rm -r /" \
        "kubectl delete" \
        "kubectl drain" \
        "terraform destroy" \
        "terraform apply -auto-approve" \
        "git push --force" \
        "git push -f" \
        "docker system prune" \
        "DROP TABLE" \
        "DROP DATABASE" \
        ": >/"
end

function __sp_needs_gate
    # Returns 0 (true) if the command string matches a gate pattern.
    set -l cmd $argv[1]
    for pattern in $SOLARPLEX_GATE_PATTERNS
        if string match -q -- "*$pattern*" $cmd
            return 0
        end
    end
    return 1
end

# ─── State ────────────────────────────────────────────────────────────────────

set -g __sp_cmd_id       ""
set -g __sp_cmd_start_ms 0
set -g __sp_gate_blocked 0

# ─── OSC-133 semantic markup helpers ─────────────────────────────────────────
# WezTerm and Rio use these to understand prompt/command/output regions.
# We call the `sp` binary so the sequences flow through its stdout — this
# ensures they work correctly even when fish itself doesn't emit them.

function __sp_osc133
    # Usage: __sp_osc133 A|B|C|D [exit_code]
    if type -q sp
        if test "$argv[1]" = D
            command sp _shell osc133 D --exit (test -n "$argv[2]"; and echo $argv[2]; or echo 0) 2>/dev/null
        else
            command sp _shell osc133 $argv[1] 2>/dev/null
        end
    end
end

# ─── Prompt hook — emit OSC-133 A (prompt start) ────────────────────────────

function __sp_prompt_start --on-event fish_prompt
    __sp_osc133 A

    # When a session is first attached (SOLARPLEX_SESSION_ID is set),
    # stash it into the WezTerm pane user var so tab titles can show it.
    if test -n "$SOLARPLEX_SESSION_ID"
        if type -q sp
            command sp _shell setvar SOLARPLEX_SESSION_ID $SOLARPLEX_SESSION_ID 2>/dev/null

            # Capture indicator: set a WezTerm user var that the wezterm.lua config
            # can surface in the tab title (e.g. "● TRACKING").
            # Value is "1" when full-command tracking is active, "0" otherwise.
            if set -q SOLARPLEX_TRACK_COMMANDS; and test "$SOLARPLEX_TRACK_COMMANDS" = "1"
                command sp _shell setvar SOLARPLEX_TRACKING 1 2>/dev/null
            else
                command sp _shell setvar SOLARPLEX_TRACKING 0 2>/dev/null
            end
        end
    end
end

# ─── Preexec hook ─────────────────────────────────────────────────────────────

function __sp_preexec --on-event fish_preexec
    # OSC-133 C = pre-execution (user has hit Enter, command is about to run).
    # We emit this here (before the gate, before start) so the terminal marks
    # the exact moment execution begins.
    __sp_osc133 C

    # Skip session tracking when no session is attached.
    if test -z "$SOLARPLEX_SESSION_ID"
        return
    end

    set -g __sp_gate_blocked 0
    set -g __sp_cmd_start_ms (date +%s%3N 2>/dev/null; or echo 0)

    set -l cmd $argv[1]

    # ── Skip tracking sp commands themselves ─────────────────────────────────
    # sp navigation (sp ask, sp act, sp session feed, etc.) and any internal
    # solarplex CLI commands are not meaningful shell work — they're the tool
    # managing the session, not the work being done inside the session.
    # Recording them creates noise in the feed ($ sp [argv not tracked] floods).
    # Also skip fish internal tokens (while, for, if, function) and empty argv.
    set -l argv0 (string split " " -- $cmd)[1]
    switch $argv0
        case sp "" while for if begin function end
            return
    end

    # ── Approval gate ────────────────────────────────────────────────────────
    # NOTE: Fish cannot cancel command execution from preexec.  The gate creates
    # a visible approval request in the Solarplex UI and blocks until resolved.
    # If denied, a warning is printed but the command still runs — for hard
    # blocking, use the `sp_require_approval` wrapper function below instead.
    if __sp_needs_gate $cmd
        set -l result (command sp approval gate -- $cmd 2>/dev/null)
        if test "$result" = "denied"
            set_color red
            echo "⚠  Solarplex supervisor denied: $cmd" >&2
            set_color normal
            set -g __sp_gate_blocked 1
        end
    end

    # ── Emit start event ─────────────────────────────────────────────────────
    # Fire-and-forget: failure is non-fatal (network may be down).
    # Pass --tracked when the user has opted in to full-command logging.
    # The client-side credential seatbelt runs inside `sp _shell start` and may
    # still suppress the full argv even when --tracked is set.
    if set -q SOLARPLEX_TRACK_COMMANDS; and test "$SOLARPLEX_TRACK_COMMANDS" = "1"
        set -g __sp_cmd_id (command sp _shell start --tracked -- $cmd 2>/dev/null)
    else
        set -g __sp_cmd_id (command sp _shell start -- $cmd 2>/dev/null)
    end
end

# ─── Postexec hook ────────────────────────────────────────────────────────────

function __sp_postexec --on-event fish_postexec
    # fish_postexec argv: [1]=command [2]=exit_status [3]=elapsed_us (3.5+)
    set -l exit_code $argv[2]
    if test -z "$exit_code"
        set exit_code 0
    end

    # OSC-133 D = command finished.  Emit regardless of session attachment
    # so WezTerm always knows where output ends.
    __sp_osc133 D $exit_code

    if test -z "$SOLARPLEX_SESSION_ID"
        return
    end
    if test -z "$__sp_cmd_id"
        return
    end

    set -l duration_ms (math (date +%s%3N 2>/dev/null) - $__sp_cmd_start_ms 2>/dev/null; or echo 0)

    # Fire and forget in background so it doesn't delay the next prompt.
    command sp _shell complete $__sp_cmd_id --exit $exit_code --ms $duration_ms 2>/dev/null &

    set -g __sp_cmd_id       ""
    set -g __sp_cmd_start_ms 0
    set -g __sp_gate_blocked 0
end

# ─── Plumb: Alt+Enter dispatches the word under the cursor ───────────────────
#
# In WezTerm: clicking an OSC-8 link invokes the URI handler (xdg-open →
# sp plumb).  In the terminal itself, Alt+Enter plumbs whatever word or
# ULID the cursor is on.

function __sp_plumb_word
    # Grab the whole commandline buffer and extract the token at cursor.
    set -l buf (commandline --cut-at-cursor)
    # Last whitespace-delimited token before cursor
    set -l word (string split -- " " $buf)[-1]
    if test -n "$word"
        # Run plumb in a subshell so it doesn't clobber the current line.
        command sp plumb run -- $word 2>&1
        commandline -f repaint
    end
end

# Bind Alt+Enter to plumb in all modes.
bind \e\r __sp_plumb_word
bind -M insert \e\r __sp_plumb_word

# ─── Helper: require approval before a command ───────────────────────────────
#
# Use this wrapper in scripts/functions for hard blocking:
#
#   function deploy
#       sp_require_approval "deploy $argv" || return 1
#       kubectl apply -f ...
#   end
#
function sp_require_approval
    set -l cmd $argv[1]
    if test -z "$SOLARPLEX_SESSION_ID"
        # No session attached — let command through (opt-in gate only)
        return 0
    end
    set -l result (command sp approval gate -- $cmd 2>/dev/null)
    switch $result
        case "granted"
            return 0
        case "denied"
            set_color red
            echo "🚫 Blocked by Solarplex supervisor: $cmd" >&2
            set_color normal
            return 1
        case '*'
            # Timeout or error — fail open (let through with a warning)
            set_color yellow
            echo "⚠  Solarplex approval timed out for: $cmd (proceeding)" >&2
            set_color normal
            return 0
    end
end

# ─── sp-enter: attach to a session and reload env in the current shell ───────
#
# Usage: sp-enter <session-id> [actor-id]
#
# sp session enter writes session.fish and prints "source ..." to stdout.
# Piping to `source` picks it up in the current fish session — env vars
# update immediately, no new shell needed.
#
# This is also what WezTerm's open-uri handler does when you click a
# solarplex:session/ID/enter link.
#
function sp-enter
    set session_id $argv[1]
    if test -z "$session_id"
        echo "Usage: sp-enter <session-id> [actor-id]" >&2
        return 1
    end
    set actor $argv[2]
    if test -n "$actor"
        command sp --actor $actor session enter $session_id | source
    else
        command sp session enter $session_id | source
    end
    echo "Entered $SOLARPLEX_SESSION_ID as $SOLARPLEX_ACTOR_ID"
end

# ─── Convenience aliases ──────────────────────────────────────────────────────

# Emit a context fact from the shell:
#   sp-note "decided to use postgres for the job queue"
function sp-note
    command sp context add --kind fact $argv
end

# Quick artifact creation from a file:
#   sp-save plan.md --type plan
function sp-save
    if test (count $argv) -lt 1
        echo "Usage: sp-save <file> [--type document|code|plan]" >&2
        return 1
    end
    set -l file $argv[1]
    set -e argv[1]
    command sp artifact create --name (basename $file) --file $file $argv
end

# Print current session status:
function sp-status
    command sp session inspect 2>/dev/null
end

# Install the solarplex: URI handler for OSC-8 link clicks:
#   sp-install-handler
function sp-install-handler
    command sp plumb run -- __install_handler__ 2>/dev/null
    # Direct call to the install helper via a dedicated sp subcommand:
    # This writes ~/.local/share/applications/solarplex-plumb.desktop
    # and runs xdg-mime default.
    echo "Run: sp _install_uri_handler" >&2
end

# ─── sp-track: toggle full-command tracking for this shell ───────────────────
#
# Full-command tracking logs the complete argv of every shell command to the
# Solarplex session event log.  This is useful for auditing but carries a risk
# of accidentally logging credentials that appear in command arguments.
#
# A client-side credential seatbelt will suppress the full argv if a known
# secret pattern is detected, but the seatbelt is a best-effort guard and
# cannot catch all forms of credential exposure (variable references, heredocs,
# encoded secrets).  Read the warning above before enabling.
#
# Usage:
#   sp-track on      # enable full-command tracking
#   sp-track off     # disable (default)
#   sp-track         # show current status
#
function sp-track
    switch (count $argv)
        case 0
            # Show status
            if set -q SOLARPLEX_TRACK_COMMANDS; and test "$SOLARPLEX_TRACK_COMMANDS" = "1"
                set_color --bold yellow
                echo "● Full-command tracking: ENABLED"
                set_color normal
                echo "  Commands are logged to the Solarplex session event log."
                echo "  The credential seatbelt is active but cannot catch all secret forms."
                echo "  Run 'sp-track off' to disable."
            else
                set_color green
                echo "○ Full-command tracking: disabled (only argv[0] is logged)"
                set_color normal
                echo "  Run 'sp-track on' to enable."
            end
        case on 1 yes
            set -gx SOLARPLEX_TRACK_COMMANDS 1
            set_color --bold yellow
            echo "● Full-command tracking ENABLED for this shell"
            set_color normal
            echo "  ⚠  Credential seatbelt active — but cannot catch all secret forms."
            echo "  Avoid commands like: mysql -pPASSWORD, psql postgresql://user:pass@host"
            echo "  Use variable references instead: git push https://\$TOKEN@host"
        case off 0 no
            set -e SOLARPLEX_TRACK_COMMANDS
            set_color green
            echo "○ Full-command tracking disabled — only argv[0] will be logged"
            set_color normal
        case '*'
            echo "Usage: sp-track [on|off]" >&2
            return 1
    end
end
