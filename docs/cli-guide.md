# sp: CLI and Shell Scripting Guide

`sp` is the Solarplex CLI. It gives you a live, navigable object environment where every session, actor, capability, artifact, approval, and context entry is a clickable entity. You browse with `sp ask`, mutate with `sp act`, and the terminal becomes a REPL over the object graph.

---

## Table of Contents

1. [Installation and Configuration](#installation-and-configuration)
2. [Authentication](#authentication)
3. [Sessions](#sessions)
4. [The ask / act Split](#the-ask--act-split)
5. [Bare-Reference Dispatch](#bare-reference-dispatch)
6. [Fish Shell Integration](#fish-shell-integration)
7. [WezTerm Workspace](#wezterm-workspace)
8. [Interactive TUI Dashboard (`sp shell`)](#interactive-tui-dashboard-sp-shell)
9. [Watching Events](#watching-events)
10. [Capabilities](#capabilities)
11. [Approvals](#approvals)
12. [Artifacts](#artifacts)
13. [Context](#context)
14. [Auth Debugging](#auth-debugging)
15. [Plumbing and Click Routing](#plumbing-and-click-routing)
16. [Scripting Reference](#scripting-reference)
17. [Subcommand Summary](#subcommand-summary)

---

## Installation and Configuration

### Environment Variables

Configuration is layered: config file, then env vars, then explicit CLI flags. Higher layers win.

| Variable | Purpose | Default |
|---|---|---|
| `SOLARPLEX_SERVER` | API server URL | `http://localhost:8080` |
| `SOLARPLEX_SESSION_ID` | Active session ULID | (none) |
| `SOLARPLEX_ACTOR_ID` | Your actor name — display/legacy only, see [Authentication](#authentication) | (none) |
| `SOLARPLEX_UI` | Web UI base URL (for clickable links, and the `sp login` handoff target) | `http://localhost:3000` |
| `SOLARPLEX_TOKEN` | Overrides the stored `sp login` credentials — for CI/scripts. Deliberately has no `--flag` equivalent: flags land in shell history and process listings, which a bearer token shouldn't. | (none) |

### Config File

Persisted automatically by `sp session attach`. You rarely edit it by hand.

- Unix: `~/.config/solarplex/session.json`
- Windows: `%APPDATA%\solarplex\session.json`

A fish-sourceable companion is written alongside it at `session.fish`. Your `sp login` credentials live in a **separate** file next to it, `credentials.json` — kept out of the fish companion deliberately, since that file gets `source`d into your shell environment and a bearer token has no business being an env var some other process can read.

### CLI Flags

All env vars have flag equivalents on every command, **except `SOLARPLEX_TOKEN`** (see above):

```
sp --server http://prod:8080 --session 01J... --actor alice session ls
```

---

## Authentication

Most of what's below now requires you to be signed in. `sp session new`, `sp cap delegate`, `sp auth why` / `who-can` / `lineage`, and anything that mutates a session used to work off a self-asserted `--actor <name>` with no real credential behind it — that's gone. The server verifies who you actually are from a bearer token, not from whatever name you typed.

```bash
sp login
```

Opens your browser, confirms you're signed in with your OIDC provider (redirecting you to sign in first if you aren't), and hands a session token back to the CLI over a one-time local callback on `127.0.0.1` — nothing to copy-paste. The token is stored in `credentials.json` next to your session config (see above) and picked up automatically by every subsequent command.

```bash
sp logout
```

Revokes the token server-side and clears it locally. Do this on a shared machine.

`--actor <name>` / `SOLARPLEX_ACTOR_ID` still exist, but they no longer assert an identity the server trusts for anything consequential — they're a display fallback and a pre-auth convenience for local multi-actor testing (mirroring the same dev-only escape hatch the web frontend has). Server-side, your real actor id, role, and permissions all come from whichever OIDC identity `sp login` authenticated as.

Agents (`shim`) don't use `sp login` at all — they authenticate via the capability token minted at attach time, which is a different, non-interactive credential. See the main [README](../README.md#6-attaching-an-agent).

---

## Sessions

A session is the top-level workspace. Everything else (actors, caps, artifacts, approvals, context) lives inside a session.

### Create and Attach

```bash
# Create a session
sp act session New --name "Payments Q3"

# Create with a specific approval policy
sp act session New --name "Payments Q3" --policy majority

# Attach to a session (saves config + prints reload instructions)
sp --actor alice session attach 01JXXXXXXXXXXXXXXXXXXXXXXXX

# Reload env in the current shell (fish)
source (sp session env | psub)
```

### List and Inspect

```bash
# List sessions (filtered to current actor)
sp session ls

# List all sessions
sp session ls --all

# Inspect the attached session
sp session inspect

# Inspect any session by ID or name
sp session inspect 01JXXX...
sp session inspect "Payments Q3"
```

### Detach

```bash
sp session detach
```

### Ownership and Lifecycle

```bash
# Transfer ownership to another actor
sp session handoff --to bob

# Show current epoch + revocation history
sp session epoch
```

The CLI still resolves a local `--from`/`--actor`/`SOLARPLEX_ACTOR_ID` value to build the request (and errors locally if none is set), but the **server** no longer trusts it — it derives "who's actually transferring" from your `sp login` identity instead, and rejects the call if that identity isn't the current owner. You can only ever hand off ownership you actually, verifiably hold.

---

## The ask / act Split

Every operation in `sp` is read-only (`ask`) or a mutation (`act`). The split is structural, not just convention.

### ask: read-only navigation

Browse entities and collections:

```bash
sp ask                              # root namespace (your attached session + all sessions)
sp ask sessions                     # all sessions
sp ask session/01JXXX               # session subgraph
sp ask session/Payments             # session resolved by name
sp ask session/01JXXX artifacts     # artifacts in that session
sp ask session/01JXXX members       # members
sp ask session/01JXXX caps          # active capability tokens
sp ask session/01JXXX context       # session context entries
sp ask session/01JXXX epoch         # epoch + revocation history
sp ask actor/alice                  # actor view
sp ask cap/01JXXX                   # cap detail + lineage
sp ask approval/01JXXX              # approval detail
sp ask artifact/01JXXX              # artifact content
```

Every entity view shows its parent refs as a clickable backtrace. An approval always knows which session requested it, regardless of how you navigated there.

Available functions on entities:

```bash
sp ask session/01JXXX pending-approvals
sp ask actor/alice why approval/01JXXX
sp ask actor/alice who-can
sp ask cap/01JXXX lineage
```

### act: mutations

Fire a transition on an entity. Transition names are PascalCase:

```bash
sp act session New --name "Payments Q3"
sp act session/01JXXX Rename --name "Payments Q3 Final"
sp act session/01JXXX OwnershipTransfer --to bob
sp act session/01JXXX Delegate --to agent-01 --ttl 900 --permissions bash_exec,read_file
sp act session/01JXXX CreateArtifact --name report.md --type document --file ./report.md
sp act session/01JXXX AddContext decision "we chose postgres for the queue"
sp act cap/01JXXX Revoke --strategy cap --drain 30
sp act approval/01JXXX Grant
sp act approval/01JXXX Deny
```

---

## Bare-Reference Dispatch

Any argument that looks like an entity reference is automatically routed to the right subcommand. You do not need to type `ask` or `act` in most cases.

```bash
sp session/42          # same as: sp ask session/42
sp artifact/01JXXX     # same as: sp ask artifact/01JXXX
sp 01JXXXXXXXXXXXXXXXXXXXXXXXX   # bare 26-char ULID: resolved automatically
```

This works from the command line and from terminal hyperlink clicks. When you see a `session/01JXXX` reference in any `sp` output, clicking it in WezTerm (or running it as a command) navigates to that entity.

---

## Fish Shell Integration

`sp` ships a fish adapter that:
- Tracks which commands you run (shell history in the session event log)
- Emits OSC-133 semantic markup (shell integration prompts)
- Sets WezTerm user vars per-pane (actor, session context)

### Setup

After attaching to a session, reload env in the current shell:

```fish
source (sp session env | psub)
```

The `sp-enter` fish function (when installed by the fish plugin) automates this. To enter a session from a pane, click the `enter` link in `sp session ls` output, or run:

```fish
sp session enter 01JXXX...
```

This writes the config file and prints `source ~/.config/solarplex/session.fish` to stdout, which the shell then evals.

### Shell Command Tracking

The fish plugin hooks into `fish_preexec` and `fish_postexec`:

```fish
# Called before each command runs
sp _shell start -- <full command>

# Called after each command completes
sp _shell complete <command_id> --exit <code> --ms <duration>
```

By default, only the command name (argv0) is tracked. To opt into full-argv tracking:

```fish
sp _shell start --tracked -- <full command>
```

The credential seatbelt runs automatically when full tracking is enabled. If it detects a secret pattern (API keys, password flags, bearer tokens), it suppresses the full argv and logs `redacted=true` instead. Variable references like `$MY_TOKEN` are safe: they appear as literal `$MY_TOKEN` in fish_preexec output, not as the token value.

### OSC-133 and WezTerm Vars

The plugin emits shell integration sequences so WezTerm can track prompt zones:

```fish
sp _shell osc133 A    # prompt-start
sp _shell osc133 B    # cmd-start
sp _shell osc133 C    # pre-exec
sp _shell osc133 D --exit <code>   # cmd-end
```

WezTerm user vars (OSC-1337) are set via:

```fish
sp _shell setvar SOLARPLEX_SESSION <session_id>
sp _shell setvar SOLARPLEX_ACTOR <actor_id>
```

---

## WezTerm Workspace

`sp session workspace` builds a multi-pane WezTerm layout for a session. It uses `wezterm cli split-pane` and `wezterm cli send-text` to set up each pane and inject commands.

```bash
# Default layout: inspect pane + feed pane
sp session workspace

# Named session
sp session workspace 01JXXX...

# Custom pane set
sp session workspace --panes inspect,feed,actors
sp session workspace --panes inspect,feed,artifacts,context
```

### Default Layout

```
┌───────────────┬────────────────────────────────┐
│  ANCHOR       │  FEED (60% wide, full height)  │
│  (40% wide,   │  Live IRC feed + interactive   │
│  65% tall)    │  shell attached to session     │
├───────────────┤                                │
│  INSPECT      │                                │
│  (35% tall,   │                                │
│  auto-refresh │                                │
│  every 10s)   │                                │
└───────────────┴────────────────────────────────┘
```

### Available Panes

| Pane | Command | Description |
|---|---|---|
| `feed` | `sp session feed` | IRC-style live message feed, interactive |
| `inspect` | `sp session inspect` | Full session view, auto-refreshes every 10 seconds |
| `actors` | `sp actor show` per member | Actor views, auto-refreshes every 15 seconds |
| `artifacts` | `sp artifact ls` | Artifact list, auto-refreshes every 15 seconds |
| `context` | `sp context ls` | Context entries, auto-refreshes every 15 seconds |

### Split a New Pane

To open a new terminal pane already attached to the current session:

```bash
sp session new-pane
sp session new-pane --split vertical
```

### WSL Notes

On WSL, `sp` looks for `wezterm.exe` in PATH, then falls back to `/mnt/c/Program Files/WezTerm/wezterm.exe`. The `$WEZTERM_PANE` environment variable must be present (WezTerm injects it per-pane; set `WSLENV=WEZTERM_PANE/u` to forward it into WSL).

---

## Interactive TUI Dashboard (`sp shell`)

```bash
sp shell
```

Launches `spsh`, a full-screen terminal dashboard for browsing sessions live — a different interaction model from the WezTerm Workspace above (one full-screen app instead of several auto-refreshing panes), any terminal, not just WezTerm. Runs alongside the one-shot `sp <verb>` commands and the fish integration above, not instead of either. First cut: navigation and hotkeys only, no scripting entry point.

### Session list

The landing screen — every session the attached actor is a member of.

| Key | Action |
|---|---|
| `Up` / `Down` | Move the selection (or click a row with the mouse) |
| `Enter` | Drill into the selected session |
| `:` | Open the command-line overlay (below) |
| `Esc` | Quit |

### Session detail

`Enter` on a session opens its detail view, with four tabs — `Tab` cycles between them, or click a tab directly:

| Tab | Shows | Extra keys |
|---|---|---|
| Members | Session membership and roles | |
| Artifacts | Artifact list | |
| Approvals | Pending/resolved approval requests | `a` grant, `d` deny the selected row |
| Chat | Message history, plus a compose line | `i` or `Enter` starts composing |

`Up`/`Down` navigate within whichever tab is active; `Esc` goes back to the session list (only the list screen's `Esc` quits). While a session's detail view is open, updates arrive live over a WebSocket connection — no manual refresh, unlike the WezTerm panes above, which poll on a fixed interval.

### Command-line overlay

Press `:` from either screen to open a modal command line on top of whatever's showing — the escape hatch for actions with no dedicated hotkey. Syntax mirrors `sp act`:

```
<entity>/<id> <Transition> [--flags] [words...]
```

Inside a session's detail view the entity/id is implicit — type just the transition:

```
OwnershipTransfer --to bob
Rename --name "New name"
Pause
Resume
Archive
AddContext --kind hypothesis some context text here
```

As you type, a debounced call to the server's intent parser (`GET /intent/parse`, `crates/intent`) shows a ghost-text suggestion underneath the input line — a preview of how your text is being parsed before you press Enter, not an LLM guess (the parser is deterministic; unparseable text just shows no suggestion, it never silently does something unexpected). `Esc` cancels without running anything. A transition not yet wired into the overlay prints a message pointing you at the equivalent `sp act <entity>/<id> <Transition> ...` instead of failing silently.

---

## Watching Events

`sp watch` is a cursor-oriented live event stream. The cursor is saved per-session so you always resume where you left off.

```bash
# Watch the attached session
sp watch

# Watch a specific session
sp watch session/01JXXX...
sp watch "Payments Q3"

# Replay from the beginning
sp watch --from 0

# Only show bundle-related events
sp watch --filter bundle

# JSON lines for piping
sp watch --json

# Custom poll interval (default 2000ms)
sp watch --interval 1000

# JSON + jq: extract event types
sp watch --json | jq -r .type
```

Press Ctrl-C to stop. The cursor is saved on exit.

Cursor files live at:
- Unix: `~/.config/solarplex/cursors/<session_id>.json`
- Windows: `%APPDATA%\solarplex\cursors\<session_id>.json`

---

## Capabilities

Capability tokens grant agents scoped, time-limited authority. The full delegation lifecycle is:

```
human (owner/collaborator)
  │
  └─ issues cap → agent
                    │
                    └─ may sub-delegate → sub-agent (only a subset)
```

### Issue a Cap

Requires you to be signed in (`sp login`) as at least a Collaborator in the session — minting a capability is granting real authority, so the server checks your role before it'll do it. Previously this had no auth check at all.

```bash
# Delegate to an agent for 15 minutes with specific tools
sp act session/01JXXX Delegate \
    --to agent-01 \
    --ttl 900 \
    --permissions bash_exec,read_file

# Expose a filesystem path via MCP
sp act session/01JXXX Delegate \
    --to agent-01 \
    --ttl 900 \
    --path /workspace/project
```

Or via the `cap` subcommand directly:

```bash
sp cap delegate --to agent-01 --permissions bash_exec --ttl 900
```

### Revoke a Cap

```bash
# Revoke a specific cap and its sub-delegations
sp cap revoke 01JXXX... --strategy cap --drain 30

# Revoke all caps at delegation depth >= 2
sp cap revoke 01JXXX... --strategy stratum --stratum 2

# Close the entire current epoch (all caps in the session)
sp cap revoke 01JXXX... --strategy epoch

# Reroot surviving children before pruning
sp cap revoke 01JXXX... --strategy cap --reroot
```

Revoked agents receive a WebSocket `cap.epoch.advanced` broadcast and are fenced after the drain window.

### Inspect Caps

```bash
sp ask session/01JXXX caps         # all caps in a session
sp ask cap/01JXXX                   # cap detail + lineage
sp auth lineage cap/01JXXX          # full delegation chain
```

---

## Approvals

Approvals gate agent actions that require human sign-off.

```bash
# List pending approvals in the attached session
sp ask approvals
sp ask session/01JXXX pending-approvals

# Wait for a specific approval to resolve
sp approval wait 01JXXX...

# Grant or deny
sp act approval/01JXXX Grant
sp act approval/01JXXX Deny
```

Approvals appear in `sp session inspect`, `sp session feed`, and the `sp watch` stream. The `sp watch --filter approval` flag shows only approval events.

---

## Artifacts

Artifacts are named blobs stored in a session: reports, code, plans, documents.

```bash
# List artifacts
sp ask session/01JXXX artifacts
sp artifact ls

# Get an artifact by ID
sp artifact get 01JXXX...
sp ask artifact/01JXXX

# Create an artifact from a file
sp act session/01JXXX CreateArtifact \
    --name report.md \
    --type document \
    --file ./report.md

# Create from stdin
cat report.md | sp act session/01JXXX CreateArtifact --name report.md
```

Artifact types: `document`, `code`, `plan`, `report`, `other`.

---

## Context

Context entries are structured notes attached to a session: decisions, facts, hypotheses, questions, constraints.

```bash
# List context
sp ask session/01JXXX context
sp context ls

# Add a context entry (kind defaults to "fact")
sp act session/01JXXX AddContext "we chose postgres for the queue"

# Add with an explicit kind
sp act session/01JXXX AddContext decision "we chose postgres for the queue"

# Show a specific entry
sp context show 01JXXX...
```

Context kinds: `fact`, `hypothesis`, `decision`, `question`, `constraint`.

---

## Auth Debugging

These commands explain why something is (or is not) allowed. They are read-only — but they now require you to be signed in (`sp login`) and a member of the session in question. These used to be completely open, unauthenticated endpoints; anyone who knew or guessed a session id could pull full membership and delegation data for it. That's closed now.

```bash
# Why can alice interact with this approval?
sp auth why actor/alice approval/01JXXX...

# Show all of alice's caps (no entity filter)
sp auth why actor/alice

# Who has authority over an artifact?
sp auth who-can artifact/01JXXX...

# Who has authority in the session, for any entity?
sp auth who-can

# Full delegation chain for a cap
sp auth lineage cap/01JXXX...

# Same commands via ask (both work)
sp ask actor/alice why approval/01JXXX...
sp ask actor/alice who-can
sp ask cap/01JXXX lineage
```

`sp auth why` shows:
- Session membership role and permissions
- All active capability tokens for the actor
- Whether each cap covers the requested entity
- The full delegation chain for each cap

`sp auth who-can` shows every actor in the session grouped by role, then by cap coverage.

`sp auth lineage` walks the parent chain from the root (human-issued) to the leaf, showing actor, permissions, and observed sequence number at each hop.

---

## Plumbing and Click Routing

The plumbing system routes text (from the command line, from terminal hyperlinks, from fish keybindings) through a rule table. First match wins.

```bash
# Route text manually
sp plumb run session/01JXXX
sp plumb run "solarplex:approval/01JXXX"

# Dry-run: show what would execute without running it
sp plumb run --dry-run session/01JXXX

# Resolve a bare ULID to its entity type
sp plumb resolve 01JXXX...
```

### Built-in Rules

| Pattern | Routes to |
|---|---|
| `solarplex:<rest>` | Strips prefix, re-routes `<rest>` |
| `session/ULID/enter` | `sp session enter <ULID>` |
| `session/ULID/workspace` | `sp session workspace <ULID>` |
| `session/ULID` | `sp ask session/<ULID>` |
| `artifact/ULID` | `sp artifact get <ULID>` |
| `approval/ULID` | `sp approval wait <ULID>` |
| `cap/ULID` | `sp cap get <ULID>` |
| `context/ULID` | `sp context show <ULID>` |
| `bare 26-char ULID` | `sp resolve <ULID>` |
| `https?://...` | `xdg-open <URL>` |

### User-Defined Rules

Add rules to `~/.config/solarplex/plumb.toml` (Unix) or `%APPDATA%\solarplex\plumb.toml` (Windows):

```toml
# Rules are matched top to bottom; first match wins.
# {0} = full match, {1} = first capture group, etc.

[[rule]]
pattern = "jira/([A-Z]+-[0-9]+)"
action  = "xdg-open https://yourco.atlassian.net/browse/{1}"

[[rule]]
pattern = "gh/([^/]+)/([^/]+)/(\\d+)"
action  = "gh pr view {3} --repo {1}/{2}"
```

User rules only run on the trusted path (direct `sp plumb run` invocations). URI-handler clicks from the terminal always use `--untrusted`, which skips user rules.

### URI Handler Installation

To make `solarplex://` URIs clickable in any app:

```bash
sp _install_uri_handler
```

This installs a `.desktop` file and registers it with `xdg-mime`. After installation, clicking a `solarplex:session/01JXXX` link in any terminal, browser, or document navigates to that entity.

---

## Scripting Reference

### Session lifecycle (script form)

```bash
#!/usr/bin/env fish

# Create a session and capture the ID
set session_id (sp act session New --name "My Session" --json | jq -r .id)

# Attach
sp --actor alice session attach $session_id
source (sp session env | psub)

# Issue a cap for an agent
sp act session/$session_id Delegate --to my-agent --ttl 3600 --permissions bash_exec

# Watch events in background
sp watch --json | jq -r .type &

# Clean up
sp session detach
```

### Polling for approvals

```bash
# Wait for any pending approval in the current session
sp watch --filter approval --json | \
    jq -r 'select(.type | contains("approval.requested")) | .payload.payload.approval_id' | \
    head -1
```

### Getting session ID from name

```bash
sp session ls --all --json 2>/dev/null | \
    jq -r '.[] | select(.name == "Payments Q3") | .id'
```

### Checking revocation epoch

```bash
sp session epoch --json | jq .epoch
```

### Feed (Live IRC-style session view)

The session feed is interactive but can be useful in scripts for log capture:

```bash
# Pipe feed to a log file (non-interactive, exits on EOF)
echo /quit | sp session feed 01JXXX > session.log
```

---

## Subcommand Summary

| Command | Purpose |
|---|---|
| `sp ask <ref> [function]` | Read-only entity navigation |
| `sp act <entity> <Transition> [args]` | Fire a mutation |
| `sp session ls / new / attach / detach` | Session lifecycle |
| `sp session inspect / feed / workspace` | Session views |
| `sp shell` | Interactive TUI dashboard (`spsh`) |
| `sp session epoch` | Revocation epoch history |
| `sp cap delegate / revoke / get` | Capability token management |
| `sp approval wait` | Wait for approval resolution |
| `sp artifact ls / get` | Artifact access |
| `sp context ls / show` | Context entries |
| `sp auth why / who-can / lineage` | Auth debugging |
| `sp watch [session]` | Live event stream |
| `sp plumb run <text>` | Route text through plumb rules |
| `sp plumb resolve <ulid>` | Identify a bare ULID |
| `sp resolve <ulid>` | Shorthand for plumb resolve |
