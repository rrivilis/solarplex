<div align="center">
  <img src=".github/assets/logo.svg" alt="Solarplex" width="112" height="112" />

  # Solarplex

  **The workflow survives its participants.**

  [![CI](https://github.com/rrivilis/solarplex/actions/workflows/ci.yml/badge.svg)](https://github.com/rrivilis/solarplex/actions/workflows/ci.yml)
  [![Version](https://img.shields.io/badge/version-0.31-blue)](https://github.com/rrivilis/solarplex/releases)
  [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
</div>

Most AI tools are built around a single-user relationship: Alice has her Claude, Bob has his GPT. When Alice leaves for the day, the workflow loses its operator. Approvals stall. Context lives in her head. An agent may deploy a refactor and nobody can trace how the change was made internally. There is no clean handoff.

Solarplex makes the **session** the root object. Operational context lives in the session, not in any individual human or agent. Multiple humans can supervise multiple agents in a persistent workspace. Agents run continuously. Ownership rotates. Context persists. Anyone who attaches sees the full picture immediately.

## Development Status

Solarplex is being actively developed and has not yet undergone an independent security audit from an external partner. The core execution and enforcement path is functional on bare-metal Linux. I would expect someone to find subtle bugs, incomplete threat coverage, and possibly design choices that could be reassessed down the road. 

Which leads to me say: please feel free to break this as you see fit. Take a look at the threat model, inspect trust boundaries, bypass it, and share any findings on where existing assumptions are in tension. Adversarial review and vulnerability reporting is very much welcomed. 

PRs encouraged also, but please keep contributions deliberate. Low effort and unverified AI-generated PRs will be closed.

## The thesis

As AI agents become joint participants in operational workflows alongside humans, the bottleneck shifts from task execution to organizational coordination. As agents become participants in shared workstreams, they assume the responsibility of acting within those workstreams by invoking services and writing to the system state. Once agents can act on a shared system state, the human-agent team acquires the coordination requirements of any distributed system: who may cause which effects, and against which view of state. 

Agents who acquire greater autonomy in executing workplace decisions, access databases, modify cloud resources, or alter internal APIs are a part of this transition. As their decisions become more consequential, and they can deploy staging or remediate incidents, we inherit implicit assumptions over how their actions are governed in production workloads. 

In response to this potential bottleneck, Solarplex operates as a governed workspace for joint human and AI work. Across its suite of services, Solarplex offers an operational environment for structured actor collaboration between humans and AI agents, where authority is typed and revocable, coordination is transactional across sessions, and the whole system is observable as a live object environment. 

---

## The problem, summarized

When Alice deploys an agent and leaves for the day, the workflow loses its human operator. Approvals stall. Escalations go nowhere. Context lives in Alice's head or in the agent's compacted memory. There is no clean handoff.

AI agent orchestration introduces shift handoffs, operational ownership, and shared governance questions that existing chat-centric tools aren't designed around solving.

Solarplex replaces the individual relationship with a shared session:

- Multiple humans attach and detach without losing context
- Agents run continuously, emitting events to a shared timeline
- Ownership rotates with a warm handoff
- Approval requests block until a qualified member responds
- Artifacts, decisions, and tool calls are attributed and auditable

The session is the primary durable object. Humans and agents participate through the session in a persistent workflow. Sessions persist independently of any individual human or agent. Participants attach and detach over time while artifacts, decisions, approvals, ownership, and operational context remain durable for workflow continuity. 

## A day in the life

Alice is supervising a coding agent responsible for a production deployment. Before ending her shift, she transfers ownership to Bob.

At 2:13 AM, the agent requests approval to apply a database migration.

Bob receives a notification and attaches to the session. He immediately sees the current owner, the pending approval request, the agent's recent artifacts, the shared context, and the most recent decisions.

He reviews the migration and approves it. The agent executes the change. Every action is logged and attributed.

Alice returns the next morning and sees the complete chain of events without needing a summary meeting.

That's the model. The session persists. Participants attach and detach. The workflow survived the handoff.

## The suite of services

Solarplex currently offers the following suite of products to support durable coordination between humans and agents across shared organizational workflows. Each of the services below is a complementary component that exposes the same operational model through different interfaces. Each component can be adopted independently, but they provide a complete environment when composed together.

| Service | Implementation Scope |
|---|---|
| Rust runtime | Reference interpreter for replay, event-sourced log, approval lifecycle, execution semantics, and threat model |
| CLI | Native shell and clickable live object environment for runtime navigation, scripting, TUI access, and REPL inspection |
| DSL | Operational and authority semantics, normalization, verification, and backend lowering |
| SaaS UI | Reference operator console for collaborative workflow management |

---

## Core concepts

**Session** — the root durable object. Owns its event log, artifacts, members, and approval state. Has a lifecycle: `active`, `suspended`, `archived`. Persists independently of any human or agent.

**Actor** — a participant, human or agent. Humans hold roles (owner, collaborator, observer). Agents have a provider, model, and tool policy. Both are first-class: every action is attributed to an actor in the event log.

**Artifact** — a document, plan, code diff, report, spreadsheet, whiteboard, or voice memo produced during the session. Carries version history. Owned by the session, not by whoever created it.

**Event** — the unit of record. Every action produces an append-only event with a monotonic sequence number: tool calls, approvals, artifact mutations, actor attach/detach, messages, ownership transfers. The event log is the audit trail, the replay source, and the UI data layer.

**ContextEntry** — a typed epistemic entry in the session's shared blackboard. Captures what participants currently believe and why (including facts, hypotheses, questions, constraints, and decisions) with full provenance. Survives agent memory compaction. Solarplex treats context as a shared operational artifact instead of relying on agent memory.

---

## Architecture

```
Human A (owner)          Human B (observer)         Human C (collaborator)
      │                        │                           │
      └────────────────────────┼───────────────────────────┘
                               │  WebSocket (sp_token)
                    ┌──────────▼──────────┐
                    │   Session Server     │
                    │  (Axum + Postgres)   │
                    │  - Event log         │
                    │  - Approval router   │
                    │  - Broadcast fan-out │
                    └──────────┬──────────┘
                               │  HTTP (attach-token exchange,
                               │  approval polling, ORB invoke —
                               │  agents never hold a live WS
                               │  connection to the server)
                    ┌──────────▼───────────────────────┐
                    │  Agent-side process stack        │
                    │  (per agent, three separate OS  │
                    │   processes: shim, adapter,      │
                    │   guardian. No single process    │
                    │   holds both approval authority and │
                    │   execution power; see docs below) │
                    └──────────┬───────────────────────┘
                               │  MCP (stdio/HTTP)
                    ┌──────────▼──────────┐
                    │  Agent              │
                    │  (Claude, GPT, etc) │
                    └──────────┬──────────┘
                               │  direct
                    ┌──────────▼──────────┐
                    │  Provider API       │
                    │  (Anthropic, etc)   │
                    └─────────────────────┘
```

The session server is **not** in the LLM inference path. It mediates tool call approvals and event fan-out only. LLM inference goes provider-direct. The agent-side stack intercepts tool calls at the MCP layer before execution, not before generation.

For internals including event sourcing, snapshot projection, ArcSwap cache, approval lifecycle, WS protocol, and design decisions, see [docs/architecture.md](docs/architecture.md). For the adversarial analysis behind the three-process split, see [docs/threat-model.md](docs/threat-model.md).

---

## Features

**Shared timeline** — every action is an event. Tool calls, approvals, handoffs, messages, and artifact changes appear in a live activity log attributed to the actor that caused them. The log is the audit trail.

**Ownership rotation and warm handoff** — ownership transfers in one command. The new owner attaches and immediately sees a handoff summary: current state, pending approvals, recent artifacts, recent decisions. No context lost.

**Needs Action panel** — approval request cards appear when agents request tool calls requiring human sign-off. Any eligible member can approve, deny, or claim to review. Contested votes surface for owner resolution.

**Artifacts** — documents, plans, code, spreadsheets, whiteboards, and voice memos live in the session store with version tracking. The artifact panel renders inline previews: syntax-highlighted code, CSV tables, rendered markdown, image thumbnails, whiteboard PNG snapshots, audio playback.

**Context layer** — a shared epistemic surface. Five entry kinds: `FACT`, `HYPOTHESIS`, `QUESTION`, `CONSTRAINT`, `DECISION`. Each entry carries actor attribution and event-log seq. Entries are resolved, not deleted, and the belief trail is preserved. Visible to any actor (human or agent) that attaches. 

**Session lifecycle** — owners can pause (suspend) or archive sessions. Suspended sessions block new work while allowing in-flight approvals to resolve. Archived sessions are fully read-only.

**CLI — `sp`** — every entity in the system has a canonical address: `session/01J...`, `artifact/01J...`, `approval/01J...`, `context/01J...`, `actor/alice`. The `sp` binary treats these as executable references. Running `sp artifact/01KABC` inspects that artifact. Bare ULIDs resolve to their type automatically. In WezTerm, every address printed to the terminal is a clickable OSC-8 link that routes through the same dispatch — click an artifact to view it, click a context entry to read it, click a session to inspect it. The entire session object graph is traversable with a click.

Beyond inspection, the CLI is a first-class participation surface. `sp session feed` opens an IRC-style live feed for the session: recent activity scrolls on entry, a prompt lets you post messages directly, and new events appear as they arrive with no browser required. `sp session workspace` splits WezTerm into a feed pane and an auto-refreshing inspect pane in one command. Artifacts can be saved to disk with `sp artifact get <id> --save FILE`. Context entries and artifacts can be created from the terminal with `sp context add` and `sp artifact create`, making the CLI a full read-write interface to the session alongside the web frontend.

---

## Running locally

### Prerequisites

- Rust (stable, 2021 edition)
- PostgreSQL 14+ (or Docker)
- Node.js 18+
- A Google OAuth 2.0 client (for sign-in; see [OIDC setup](#2-oidc-setup) below)

### Platform note

The server, frontend, CLI, and sidecar are cross-platform (they build and run fine natively on Windows). **`shim` and `guardian` do not** because they use Unix domain sockets for IPC and Linux-only sandboxing (`bwrap`, Landlock, `PR_SET_NO_NEW_PRIVS`), so agent attachment must happen from a real Linux shell: native Linux, macOS, or **WSL2** on Windows. If you're on Windows, run everything through a WSL2 Ubuntu shell rather than PowerShell. It's simpler than juggling two toolchains, and it's what actually gets exercised. Commands below are POSIX shell (bash/zsh/fish-compatible with `export`/`$VAR` swapped for fish's `set -gx`); a native-Windows PowerShell reader only needs this for the server, frontend, and CLI, and can swap `export X=Y` for `$env:X = "Y"`.

### 1. Database

```bash
docker run -d --name solarplex-pg \
  --restart unless-stopped \
  -e POSTGRES_PASSWORD=solarplex \
  -p 5433:5432 \
  postgres:16-alpine

docker exec -it solarplex-pg psql -U postgres -c "CREATE DATABASE solarplex;"
```

`--restart unless-stopped` matters: without it, the container doesn't come back after Docker Desktop or WSL restarts, and every service above it starts failing with "pool timed out waiting for an open connection" — that's a dead Postgres, not an app bug. `docker ps -a` and `docker start solarplex-pg` are the first things to check if the server won't connect.

**Native PostgreSQL** (skip Docker entirely): `psql -U postgres -c "CREATE DATABASE solarplex;"`, then point `DATABASE_URL` at port 5432 instead of 5433 below.

### 2. OIDC setup

Sign-in is real OIDC now, not a dev placeholder — the server refuses to start the sign-in flow at all without it configured (`GET /auth/oidc/start` returns 501 "OIDC not configured"). For local dev:

1. [Google Cloud Console](https://console.cloud.google.com) → APIs & Services → Credentials → **Create Credentials → OAuth client ID** → Application type **Web application**.
2. Add an **Authorized redirect URI**: `http://localhost:8080/auth/oidc/callback` — this must match `OIDC_REDIRECT_URI` below exactly.
3. Copy the generated Client ID and Client Secret.

```bash
export OIDC_ISSUER_URL=https://accounts.google.com
export OIDC_CLIENT_ID=<from the console>
export OIDC_CLIENT_SECRET=<from the console>
export OIDC_REDIRECT_URI=http://localhost:8080/auth/oidc/callback
export OIDC_FRONTEND_REDIRECT=http://localhost:3000
```

`OIDC_FRONTEND_REDIRECT` isn't optional for a split frontend/backend setup like this one, despite defaulting to `/` — that default resolves against the *server's own* origin (`:8080`), not the frontend (`:3000`), so sign-in silently bounces to the wrong port if you skip it. Any other OIDC provider works too (Okta, Auth0, a self-hosted one) — just point `OIDC_ISSUER_URL` at its discovery-capable issuer URL and register the same redirect URI with it.

### 3. Server

```bash
# Docker Postgres on port 5433:
export DATABASE_URL="postgres://postgres:solarplex@localhost:5433/solarplex"
# Native Postgres on port 5432:
# export DATABASE_URL="postgres://postgres:solarplex@localhost/solarplex"

export BIND_ADDR="0.0.0.0:8080"
# ...plus the five OIDC_* vars from the previous step, in the same shell.

cargo run -p server
```

Migrations run automatically on startup. Server listens on `http://localhost:8080`.

### 4. Frontend

```bash
cd frontend
npm install
npm run dev    # http://localhost:3000
```

Defaults to `NEXT_PUBLIC_API_URL=http://localhost:8080/api` and `NEXT_PUBLIC_WS_URL=ws://localhost:8080` if unset — fine for local dev, but a **production build (`npm run build` with `NODE_ENV=production`) now fails loudly if either is unset**, rather than silently shipping a `localhost` default to every visitor's browser. Set both explicitly for any real deployment.

Open `http://localhost:3000` and sign in with Google — that's your identity now, not an env var. (`NEXT_PUBLIC_ACTOR_ID` / `?actor=` still exist as a pre-auth convenience for exercising multiple actors against one dev server without juggling multiple Google accounts, but they're compiled out entirely in production builds — `next build` refuses to proceed if `NEXT_PUBLIC_ACTOR_ID` is set with `NODE_ENV=production`.)

### 4b. Desktop shell (Tauri)

`frontend/src-tauri` wraps the same frontend in a native window — no separate UI to maintain, the desktop app just points its webview at a URL:

```bash
cd frontend
npm run tauri dev
```

`beforeDevCommand` in `src-tauri/tauri.conf.json` starts `next dev` automatically, so you don't need step 4 running separately first. The window loads `http://localhost:3000`, same as a browser tab — sign-in, WS streaming, and everything else works identically since nothing in the frontend depends on Next.js server-only features (no API routes, no middleware, no server actions); it's a pure client against `NEXT_PUBLIC_API_URL`/`NEXT_PUBLIC_WS_URL`, which is exactly what a thin native wrapper needs.

`src-tauri/tauri.conf.json`'s `build.frontendDist` is also set to `http://localhost:3000` right now — before shipping a real desktop build (`npm run tauri build`), point it at the actual deployed frontend origin instead. `identifier` is `com.solarplex.desktop`; the crate is deliberately its own Cargo workspace (`[workspace]` in `src-tauri/Cargo.toml`) so it stays independent of the Rust backend's workspace at the repo root.

Chosen with an eye toward Tauri's mobile targets (iOS/Android) reusing this same setup later — two things that matters for that path and are worth keeping in mind now: nothing here should grow a dependency on Next.js server-only rendering, and the OIDC sign-in flow (`lib/auth.ts`'s `signIn()`, a plain `window.location.href` redirect) will likely need to route through the system browser instead of the in-app webview once a mobile build exists, since providers like Google block sign-in inside embedded mobile webviews. Desktop's own OS webviews (WebView2/WKWebView) aren't targeted by that block, so the current in-webview flow works as-is here.

### 5. CLI

```bash
cargo build -p cli
./target/debug/sp login
```

`sp login` opens your browser, confirms you're signed in (redirecting to Google first if you aren't), and hands a session token back to the CLI over a one-time local callback — no manual token copying. From there `sp session ls`, `sp auth why`, `sp session feed`, etc. all just work. Full command reference: [docs/cli-guide.md](docs/cli-guide.md).

Shell-command tracking and clickable OSC-8 entity links come from a per-shell adapter — pick the one matching your shell, both have the same feature set:

- **fish**: `shell/solarplex.fish` see that file's header comment for the one-line install.
- **bash / zsh / Oils (OSH mode)**: `shell/solarplex.sh` same install shape:
  ```bash
  cp shell/solarplex.sh ~/.solarplex.sh
  echo 'source ~/.solarplex.sh' >> ~/.bashrc   # or ~/.zshrc
  sp session attach <id> --actor <you>
  ```
  Oils hasn't been tested against directly, but the adapter only uses mechanisms OSH is explicitly designed to run unmodified (bash's `DEBUG` trap, `PROMPT_COMMAND`, `bind -x`). See that file's own header comment for the caveat.

**Click-to-open compatibility**: every adapter above emits the same OSC-8 links; whether clicking one actually opens something depends on your terminal emulator, not the adapter. Verified so far:
- **WezTerm**: fully working. `shell/wezterm.lua` has the ready-to-use config (handles the WSL handoff and the click itself; no OS-level URI handler needed). Currently the only terminal that makes the object graph fully clickable end-to-end; future compatibility on other terminal emulators is TBD.
- **Windows Terminal**: hardcoded to only launch `http:`/`https:`/`file:` links ([microsoft/terminal#7562](https://github.com/microsoft/terminal/issues/7562), still true as of the abandoned [#15700](https://github.com/microsoft/terminal/pull/15700) spec). `solarplex://` links render and underline correctly but will never open by design. 
- Everywhere else: untested. Run `sp _install_uri_handler` to register the OS-level handoff (xdg-mime on Linux, the Windows registry on Windows) and see if your terminal calls through to it.

Interactive object graph navigation is currently supported in WezTerm. Solarplex uses terminal hyperlinks and URI dispatch to make sessions, artifacts, approvals, and capabilities directly navigable from the terminal. Compatibility with other terminal is an area for further exploration.

### 6. Attaching an agent

The generated launch command runs `sp`'s companion `shim` binary, not `sidecar` directly — `shim` is the actual entry point; it does the token exchange, then spawns `guardian` (sandboxing) and `sidecar` (the MCP proxy) as children over an inherited IPC socket. Running `sidecar` on its own doesn't work — it expects that socket to already exist.

**In the UI** (you need Collaborator role or higher in the session — this now requires being signed in, not just knowing a session id):
1. Open the session and click **Attach Agent** in the top bar
2. Fill in the agent ID (e.g. `fs-agent`) and the filesystem path to allow
3. Copy the generated launch command — it already contains the one-time token, a **per-agent `SIDECAR_PORT`**, and the full `cargo run -p shim` invocation
4. Copy the **MCP URL** shown alongside it — that's what you point your MCP client at

It looks like:

```bash
export SOLARPLEX_TOKEN="<one-time-token-from-ui>"
export UPSTREAM_MCP_CMD="npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir"
export SIDECAR_PORT="<per-agent port from the UI>"
cargo run -p shim
```

On startup, `shim` exchanges the token for its session ID, actor ID, cap ID, and permitted tool list via `POST /api/attach`, then discards the raw token — it's single-use and can't be replayed. To reattach, click **Attach Agent** again for a fresh one. This whole step must run in a Linux/WSL2 shell — see the [platform note](#platform-note) above.

Point the agent's MCP client (e.g. Claude Code `--mcp-url`) at the **MCP URL** the UI showed you for this specific agent (`http://localhost:<that agent's port>`) — copy it from there, don't hardcode a port. `SIDECAR_PORT` is derived per cap (a deterministic hash of the cap id into `20000..=29999`), not a fixed value shared by every agent: two agents attached around the same time land on different ports, so whichever one Claude Code is actually talking to can't silently swap out from under you the way it could when every agent defaulted to the same `7777`. If you're only ever running one agent at a time by hand and want a fixed, memorable port instead, you can still override it — just export `SIDECAR_PORT` yourself *after* pasting the generated command, before running `cargo run -p shim`. The sidecar intercepts every tool call, applies the approval policy, and injects the Solarplex meta-tools (`solarplex_create_artifact`, `solarplex_post_message`, `solarplex_add_context`, etc.) into the tool list.

> **HTTP upstream (alternative):** If your MCP server already exposes an HTTP endpoint instead of using a stdio subprocess, set `UPSTREAM_MCP_URL=http://localhost:3001` instead of `UPSTREAM_MCP_CMD`.

---

## API quickstart

Session creation and most session-mutating endpoints require a real bearer token now — the old "just POST a `created_by` field" flow is gone; a self-asserted identity in the request body is no longer trusted for anything that grants access or changes ownership. The easiest path is the CLI, which already holds your token after `sp login`:

```bash
sp session new "Q3 research" --policy single_vote
sp --session <id> auth why actor/<your-name>          # confirm your own role/caps
```

To hit the REST API directly (e.g. from a script), grab the token `sp login` already stored — `jq -r .sp_token ~/.config/solarplex/credentials.json` on Linux/WSL/macOS, or `%APPDATA%\solarplex\credentials.json` on native Windows — and pass it as a bearer header:

```bash
TOKEN=$(jq -r .sp_token ~/.config/solarplex/credentials.json)

# Create a session (created_by is derived from the token now, not the body)
curl -s -X POST http://localhost:8080/api/sessions \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Q3 research","approval_policy":"single_vote"}' | jq .

# Transfer ownership — "from" is derived from the token too; you can only
# transfer away ownership you actually, verifiably hold
curl -s -X POST http://localhost:8080/api/sessions/<session-id>/transfer \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"to":"<other-actor-id>"}' | jq .
```

Agents authenticate differently via the capability token (`cap_id`) minted at attach time, not a bearer header; see [Attaching an agent](#6-attaching-an-agent) above. That's handled for you by `shim`; you shouldn't need to construct those calls by hand.
