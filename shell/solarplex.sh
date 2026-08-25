# solarplex.sh — bash/zsh (and Oils' bash-compatible OSH mode) adapter for
# Solarplex — POSIX-syntax counterpart to solarplex.fish; see that file for
# the original design notes. Same feature set, translated syntax, with two
# real mechanism differences called out where they occur (hook registration,
# Alt+Enter keybinding) since bash and zsh don't share fish's `--on-event`
# system.
#
# Tracks every shell command as a session event so the Solarplex UI shows
# a live shell timeline alongside agent actions and approvals.
#
# Installation (bash):
#   cp shell/solarplex.sh ~/.solarplex.sh
#   echo 'source ~/.solarplex.sh' >> ~/.bashrc
#   sp session attach <id> --actor <you>
#   source (sp session env --shell posix) # or: source <(sp session env --shell posix)
#
# Installation (zsh):
#   cp shell/solarplex.sh ~/.solarplex.sh
#   echo 'source ~/.solarplex.sh' >> ~/.zshrc
#   sp session attach <id> --actor <you>
#   source <(sp session env --shell posix)
#
# Requires `sp` binary installed in PATH: cargo build -p cli, then put
# target/debug (or target/release) on PATH.
#
# Oils (OSH mode): OSH is explicitly designed to run existing bash scripts
# unmodified — this file has not been tested against it directly, but it
# uses nothing beyond the bash mechanisms below (DEBUG trap, PROMPT_COMMAND,
# `bind -x`), which is exactly what OSH targets compatibility with. If
# something here doesn't work under OSH, it's likely one of those three.

# ─── Detect which shell is actually running ──────────────────────────────────
#
# $BASH_VERSION / $ZSH_VERSION are the standard, reliable way to tell these
# apart at runtime — unlike $SHELL (the user's *login* shell, not
# necessarily this one) or $0 (unreliable when sourced).

if [ -n "${BASH_VERSION:-}" ]; then
    __sp_shell=bash
elif [ -n "${ZSH_VERSION:-}" ]; then
    __sp_shell=zsh
else
    # Not bash or zsh — the shared logic below is plain POSIX and still
    # works if sourced (e.g. under a stricter OSH mode, or dash for
    # testing), but the hook registration and Alt+Enter binding sections
    # are skipped: both need one of the two branches below by construction.
    __sp_shell=posix
fi

# ─── Shell-kind signal ────────────────────────────────────────────────────────
#
# Lets `sp plumb run` (clicking an OSC-8 session/<id>/enter link) know which
# adapter is loaded, so it emits `source ~/.config/solarplex/session.sh`
# rather than guessing — see crates/cli/src/cmd/plumb.rs::detected_shell_kind.
export SOLARPLEX_SHELL_KIND=posix

# ─── Load persisted session config ───────────────────────────────────────────

__sp_load_config() {
    # POSIX-sourceable config written by `sp session attach`/`sp session
    # enter` — see config::posix_env_path(). Fish's companion is
    # session.fish; this is session.sh, always written alongside it.
    sp_cfg="$HOME/.config/solarplex/session.sh"
    if [ -f "$sp_cfg" ]; then
        . "$sp_cfg"
    fi
    unset sp_cfg
}
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
#   export SOLARPLEX_TRACK_COMMANDS=1      # enable for this shell
#   unset SOLARPLEX_TRACK_COMMANDS         # disable
#
# Even when enabled a client-side credential seatbelt will suppress the full
# argv if it detects a known secret pattern (URL credentials, --password flags,
# inline env-var assignments like AWS_SECRET_ACCESS_KEY=xxx, GitHub/Anthropic/
# OpenAI token literals, etc.). The event will be stored with redacted=true
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
# Override by setting $SOLARPLEX_GATE_PATTERNS (a bash/zsh array) before
# this file is sourced.

if [ -z "${SOLARPLEX_GATE_PATTERNS+x}" ]; then
    SOLARPLEX_GATE_PATTERNS=(
        "rm -rf"
        "rm -r /"
        "kubectl delete"
        "kubectl drain"
        "terraform destroy"
        "terraform apply -auto-approve"
        "git push --force"
        "git push -f"
        "docker system prune"
        "DROP TABLE"
        "DROP DATABASE"
        ": >/"
    )
fi

__sp_needs_gate() {
    # Returns 0 (true, POSIX exit-status sense) if $1 matches a gate pattern.
    cmd=$1
    for pattern in "${SOLARPLEX_GATE_PATTERNS[@]}"; do
        case "$cmd" in
            *"$pattern"*) return 0 ;;
        esac
    done
    return 1
}

# ─── Colour helpers ───────────────────────────────────────────────────────────
# fish's set_color by name; raw ANSI here since neither bash nor zsh has a
# built-in equivalent worth depending on.
__sp_c_red()    { printf '\033[31m'; }
__sp_c_yellow() { printf '\033[33m'; }
__sp_c_green()  { printf '\033[32m'; }
__sp_c_bold_yellow() { printf '\033[1;33m'; }
__sp_c_reset()  { printf '\033[0m'; }

# ─── State ────────────────────────────────────────────────────────────────────

__sp_cmd_id=""
__sp_cmd_start_ms=0
__sp_gate_blocked=0
# Arms after each prompt is drawn, disarmed by the first DEBUG-trap firing —
# see the bash hook-registration section below for why bash specifically
# needs this (fish and zsh's native hooks don't).
__sp_ready_for_preexec=1
# True while running inside the postexec/precmd hook itself, so bash's raw
# DEBUG trap (which fires before *every* simple command, including ones
# inside our own hook) doesn't mistake our own bookkeeping for a new
# user command.
__sp_in_precmd=""
# Set to 1 only as the literal last line of this file (see the bottom).
# Bash's DEBUG trap fires for every simple command *from the moment it's
# installed*, which is partway through this very file (the hook
# registration section below) — without this guard, the `if`/`bind -x`
# statements later in this same script would themselves fire the trap
# and consume __sp_ready_for_preexec before the user's shell is even
# ready, so the very next real command a user types would silently not
# fire preexec. Checked first, before any other guard, in __sp_debug_trap.
__sp_loaded=""

# ─── OSC-133 semantic markup helpers ─────────────────────────────────────────
# WezTerm and Rio use these to understand prompt/command/output regions.
# We call the `sp` binary so the sequences flow through its stdout — this
# ensures they work correctly even when the shell itself doesn't emit them.

__sp_osc133() {
    # Usage: __sp_osc133 A|B|C|D [exit_code]
    command -v sp >/dev/null 2>&1 || return 0
    if [ "$1" = D ]; then
        exit_code=${2:-0}
        command sp _shell osc133 D --exit "$exit_code" 2>/dev/null
    else
        command sp _shell osc133 "$1" 2>/dev/null
    fi
}

# ─── Shared preexec/postexec logic ────────────────────────────────────────────
#
# Both hook registrations below (bash's DEBUG-trap dance, zsh's native
# add-zsh-hook) normalize down to calling these two with the same
# arguments, so the actual tracking logic — gate check, argv0 extraction,
# credential seatbelt opt-in, OSC-133 markers, sp_shell start/complete — is
# written once instead of twice.

# $1 = full command line about to run.
__sp_preexec() {
    cmd=$1

    # OSC-133 C = pre-execution (user has hit Enter, command is about to
    # run). Emitted here (before the gate, before start) so the terminal
    # marks the exact moment execution begins.
    __sp_osc133 C

    # Skip session tracking when no session is attached.
    if [ -z "${SOLARPLEX_SESSION_ID:-}" ]; then
        return
    fi

    __sp_gate_blocked=0
    __sp_cmd_start_ms=$(date +%s%3N 2>/dev/null || echo 0)

    # ── Skip tracking sp commands themselves ─────────────────────────────
    # sp navigation (sp ask, sp act, sp session feed, etc.) is session
    # management, not user work — recording it creates noise in the feed.
    # (fish's adapter additionally skips fish's own compound-statement
    # keywords, needed there because fish_preexec's firing granularity
    # differs; bash/zsh's "fire once per prompt cycle" guard in the hook
    # registration below already covers that case here, so this list only
    # needs to cover sp itself.)
    argv0=${cmd%% *}
    argv0=${argv0##*/}
    if [ -z "$cmd" ] || [ "$argv0" = "sp" ]; then
        return
    fi

    # ── Approval gate ────────────────────────────────────────────────────
    # NOTE: like the fish adapter, this cannot cancel command execution —
    # bash/zsh's DEBUG trap and precmd/preexec hooks observe, they don't
    # intercept. The gate creates a visible approval request and blocks
    # until resolved; if denied, a warning prints but the command still
    # runs. For hard blocking use the sp_require_approval wrapper below.
    if __sp_needs_gate "$cmd"; then
        result=$(command sp approval gate -- "$cmd" 2>/dev/null)
        if [ "$result" = "denied" ]; then
            __sp_c_red; printf '⚠  Solarplex supervisor denied: %s\n' "$cmd" >&2; __sp_c_reset
            __sp_gate_blocked=1
        fi
    fi

    # ── Emit start event ─────────────────────────────────────────────────
    # Fire-and-forget: failure is non-fatal (network may be down). Pass
    # --tracked when the user has opted in to full-command logging. The
    # client-side credential seatbelt runs inside `sp _shell start` and may
    # still suppress the full argv even when --tracked is set.
    if [ "${SOLARPLEX_TRACK_COMMANDS:-}" = "1" ]; then
        __sp_cmd_id=$(command sp _shell start --tracked -- "$cmd" 2>/dev/null)
    else
        __sp_cmd_id=$(command sp _shell start -- "$cmd" 2>/dev/null)
    fi
}

# $1 = exit code of the command that just finished.
__sp_precmd() {
    exit_code=$1

    # OSC-133 D = command finished. Emitted regardless of session
    # attachment so the terminal always knows where output ends.
    __sp_osc133 D "$exit_code"

    if [ -z "${SOLARPLEX_SESSION_ID:-}" ] || [ -z "$__sp_cmd_id" ]; then
        return
    fi

    now_ms=$(date +%s%3N 2>/dev/null || echo 0)
    duration_ms=$(( now_ms - __sp_cmd_start_ms ))

    # Fire and forget in background so it doesn't delay the next prompt.
    command sp _shell complete "$__sp_cmd_id" --exit "$exit_code" --ms "$duration_ms" >/dev/null 2>&1 &

    __sp_cmd_id=""
    __sp_cmd_start_ms=0
    __sp_gate_blocked=0
}

# ─── Hook registration — the one real mechanism difference ──────────────────

if [ "$__sp_shell" = bash ]; then
    # Bash has no native preexec/postexec event system (unlike fish/zsh) —
    # the standard technique (used by bash-preexec, direnv, starship, etc.)
    # combines two hook points:
    #   DEBUG trap     — fires before every *simple* command; this is "preexec".
    #   PROMPT_COMMAND — fires right before the next prompt is drawn, i.e.
    #                    right after the previous command finished; "postexec".
    #
    # If a preexec framework is already loaded (bash-preexec itself, or
    # anything providing the same preexec_functions/precmd_functions
    # arrays — starship's and atuin's bash integration both do), hook into
    # that instead of installing a raw DEBUG trap, so this composes with
    # whatever else is already hooked rather than silently overwriting it.
    # Known gap: bash only allows *one* DEBUG trap handler at a time (unlike
    # PROMPT_COMMAND, which is just string concatenation) — if something
    # else sets a raw `trap ... DEBUG` directly, outside any framework,
    # ours replaces it in the fallback branch below. Documented, not
    # silently swept under the rug.
    if declare -p preexec_functions >/dev/null 2>&1; then
        preexec_functions+=(__sp_preexec)
        precmd_functions+=(__sp_precmd_bash_framework)
        __sp_precmd_bash_framework() { __sp_precmd "$?"; }
    else
        # DEBUG fires before *every* simple command, including each
        # iteration of a loop and each branch of an if — not just once per
        # line typed at the prompt, unlike fish's fish_preexec. Only the
        # first firing after a prompt is drawn corresponds to "a new
        # top-level command started"; __sp_ready_for_preexec is armed by
        # the precmd wrapper and disarmed by the first DEBUG firing, so
        # every subsequent firing for the same compound command is a no-op.
        # This is the same technique bash-preexec uses for the same reason.
        __sp_debug_trap() {
            [ -z "$__sp_loaded" ] && return
            [ -n "$__sp_in_precmd" ] && return
            [ -z "$__sp_ready_for_preexec" ] && return
            __sp_ready_for_preexec=""
            __sp_preexec "$BASH_COMMAND"
        }
        __sp_precmd_wrapper() {
            ec=$?
            __sp_in_precmd=1
            __sp_precmd "$ec"
            __sp_in_precmd=""
            __sp_ready_for_preexec=1
            return "$ec"
        }
        # Let the DEBUG trap propagate into shell functions and subshells
        # too — otherwise commands run *through* a function you've defined
        # would never trigger preexec at all.
        set -o functrace
        trap '__sp_debug_trap' DEBUG
        PROMPT_COMMAND="__sp_precmd_wrapper${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    fi

elif [ "$__sp_shell" = zsh ]; then
    # zsh has first-class, multi-subscriber hooks (add-zsh-hook is zsh's
    # equivalent of fish's --on-event) — no DEBUG-trap workaround needed,
    # and no "fire once per prompt" guard either: zsh's preexec already
    # fires exactly once per top-level command line, like fish's.
    autoload -Uz add-zsh-hook 2>/dev/null
    __sp_preexec_zsh() { __sp_preexec "$1"; }
    __sp_precmd_zsh()  { local ec=$?; __sp_precmd "$ec"; }
    add-zsh-hook preexec __sp_preexec_zsh
    add-zsh-hook precmd  __sp_precmd_zsh
fi

# ─── Plumb: Alt+Enter dispatches the word under the cursor ───────────────────
#
# In WezTerm: clicking an OSC-8 link invokes the URI handler (xdg-open →
# sp plumb). In the terminal itself, Alt+Enter plumbs whatever word or
# ULID the cursor is on — same feature as the fish adapter, but bash and
# zsh expose the command-line buffer through genuinely different APIs
# (bash: $READLINE_LINE/$READLINE_POINT inside a `bind -x` function; zsh:
# $BUFFER/$CURSOR inside a ZLE widget), so the buffer-extraction step is
# shell-specific even though the actual plumb dispatch isn't.

__sp_plumb_run_word() {
    word=$1
    [ -n "$word" ] || return
    command sp plumb run -- "$word" 2>&1
}

if [ "$__sp_shell" = bash ]; then
    __sp_plumb_word_bash() {
        # READLINE_LINE/READLINE_POINT are only populated when this
        # function is invoked via `bind -x` — not callable standalone.
        before_cursor=${READLINE_LINE:0:READLINE_POINT}
        word=${before_cursor##* }
        __sp_plumb_run_word "$word"
    }
    bind -x '"\e\r": __sp_plumb_word_bash' 2>/dev/null

elif [ "$__sp_shell" = zsh ]; then
    __sp_plumb_word_zsh() {
        # $BUFFER/$CURSOR are only populated inside a ZLE widget context —
        # zsh string indexing is 1-based, so [1,CURSOR] is "start through
        # cursor", the same slice fish's `commandline --cut-at-cursor` gives.
        local before_cursor=${BUFFER[1,CURSOR]}
        local word=${before_cursor##* }
        __sp_plumb_run_word "$word"
        zle redisplay
    }
    zle -N __sp_plumb_word_zsh
    bindkey '\e\r' __sp_plumb_word_zsh
fi

# ─── Helper: require approval before a command ───────────────────────────────
#
# Use this wrapper in scripts/functions for hard blocking:
#
#   deploy() {
#       sp_require_approval "deploy $*" || return 1
#       kubectl apply -f ...
#   }
#
sp_require_approval() {
    cmd=$1
    if [ -z "${SOLARPLEX_SESSION_ID:-}" ]; then
        # No session attached — let command through (opt-in gate only)
        return 0
    fi
    result=$(command sp approval gate -- "$cmd" 2>/dev/null)
    case "$result" in
        granted)
            return 0 ;;
        denied)
            __sp_c_red; printf '🚫 Blocked by Solarplex supervisor: %s\n' "$cmd" >&2; __sp_c_reset
            return 1 ;;
        *)
            # Timeout or error — fail open (let through with a warning)
            __sp_c_yellow; printf '⚠  Solarplex approval timed out for: %s (proceeding)\n' "$cmd" >&2; __sp_c_reset
            return 0 ;;
    esac
}

# ─── sp-enter: attach to a session and reload env in the current shell ───────
#
# Usage: sp-enter <session-id> [actor-id]
#
# sp session enter writes session.sh and prints "source ..." to stdout.
# Piping to `source` picks it up in the current shell — env vars update
# immediately, no new shell needed.
#
sp-enter() {
    session_id=$1
    if [ -z "$session_id" ]; then
        printf 'Usage: sp-enter <session-id> [actor-id]\n' >&2
        return 1
    fi
    actor=$2
    if [ -n "$actor" ]; then
        . <(command sp --actor "$actor" session enter "$session_id" --shell posix)
    else
        . <(command sp session enter "$session_id" --shell posix)
    fi
    printf 'Entered %s as %s\n' "$SOLARPLEX_SESSION_ID" "$SOLARPLEX_ACTOR_ID"
}

# ─── Convenience aliases ──────────────────────────────────────────────────────

# Emit a context fact from the shell:
#   sp-note "decided to use postgres for the job queue"
sp-note() {
    command sp context add --kind fact "$@"
}

# Quick artifact creation from a file:
#   sp-save plan.md --type plan
sp-save() {
    if [ $# -lt 1 ]; then
        printf 'Usage: sp-save <file> [--type document|code|plan]\n' >&2
        return 1
    fi
    file=$1
    shift
    command sp artifact create --name "$(basename "$file")" --file "$file" "$@"
}

# Print current session status:
sp-status() {
    command sp session inspect 2>/dev/null
}

# Install the solarplex: URI handler for OSC-8 link clicks:
#   sp-install-handler
sp-install-handler() {
    printf 'Run: sp _install_uri_handler\n' >&2
}

# ─── sp-track: toggle full-command tracking for this shell ───────────────────
#
# Full-command tracking logs the complete argv of every shell command to the
# Solarplex session event log. This is useful for auditing but carries a risk
# of accidentally logging credentials that appear in command arguments.
#
# A client-side credential seatbelt will suppress the full argv if a known
# secret pattern is detected, but the seatbelt is a best-effort guard and
# cannot catch all forms of credential exposure (variable references, heredocs,
# encoded secrets). Read the warning above before enabling.
#
# Usage:
#   sp-track on      # enable full-command tracking
#   sp-track off     # disable (default)
#   sp-track         # show current status
#
sp-track() {
    case "${1:-}" in
        "")
            if [ "${SOLARPLEX_TRACK_COMMANDS:-}" = "1" ]; then
                __sp_c_bold_yellow
                printf '● Full-command tracking: ENABLED\n'
                __sp_c_reset
                printf '  Commands are logged to the Solarplex session event log.\n'
                printf '  The credential seatbelt is active but cannot catch all secret forms.\n'
                printf "  Run 'sp-track off' to disable.\n"
            else
                __sp_c_green
                printf '○ Full-command tracking: disabled (only argv[0] is logged)\n'
                __sp_c_reset
                printf "  Run 'sp-track on' to enable.\n"
            fi
            ;;
        on|1|yes)
            export SOLARPLEX_TRACK_COMMANDS=1
            __sp_c_bold_yellow
            printf '● Full-command tracking ENABLED for this shell\n'
            __sp_c_reset
            printf '  ⚠  Credential seatbelt active — but cannot catch all secret forms.\n'
            printf '  Avoid commands like: mysql -pPASSWORD, psql postgresql://user:pass@host\n'
            printf '  Use variable references instead: git push https://$TOKEN@host\n'
            ;;
        off|0|no)
            unset SOLARPLEX_TRACK_COMMANDS
            __sp_c_green
            printf '○ Full-command tracking disabled — only argv[0] will be logged\n'
            __sp_c_reset
            ;;
        *)
            printf 'Usage: sp-track [on|off]\n' >&2
            return 1
            ;;
    esac
}

# ─── End of file — must stay last, see __sp_loaded's own comment above ──────
__sp_loaded=1
