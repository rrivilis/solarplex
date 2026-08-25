# Solarplex — Architecture

Technical reference for the session server, the agent-side execution stack (adapter/shim/guardian), the state model, approval lifecycle, and WebSocket protocol. For the product overview and quickstart, see [README.md](README.md). For the adversarial analysis behind every claim in this document — attack surface, trust boundaries, what's prevented vs. merely detected — see [threat-model.md](threat-model.md), which this doc defers to rather than duplicates. For the `sp` CLI in depth, see [cli-guide.md](cli-guide.md); for the Lisp-based authority DSL (`sp-dsl/`) that [Cap revocation semantics](#cap-revocation-semantics) and [Secrets management](#secrets-management) both touch on, see [dsl-guide.md](dsl-guide.md).

## The core model

One barrier, two questions, three rings.

Different substrates provide different enforceability guarantees, so every mutation an agent can produce is classified into one of three rings, and authority + consistency are checked at a common commit barrier:

| Ring | Also called | Applies to | Commit primitive | Guarantee |
|---|---|---|---|---|
| **0** | Tier 1 | Solarplex-managed state (artifacts, context entries) | Postgres CAS, one transaction | **Prevention** — cannot land against stale state |
| **1** | Tier 2 | Filesystem writes | POSIX write + before/after attestation | **Detection-in-log only** — POSIX has no CAS primitive, for any party |
| **2** | Tier 3 | Shell / imperative (`solarplex_exec`) | Human approval + runahead scout + kernel sandbox | **Prevention (sandbox)** for declared effects **+ detection** for divergence |

"Ring" and "Tier" name the identical three-level model — `docs/threat-model.md` §4.4 and `crates/protocol/src/effects.rs` use Ring-0/1/2; the SQL migrations and `crates/db/src/proposals.rs` use Tier-1/2/3. Both orderings appear in this doc depending on which layer is being described; they always mean the same thing. The commit barrier checks two orthogonal invariants at the same point — **authority** (cap DAG: may this principal cause this effect?) and **consistency** (CAS hash: may this effect land against the state it claims to have read?). Ring 0 enforces both. Ring 1 enforces authority; consistency is detected post-hoc. Ring 2 enforces authority; consistency is delegated to the human, augmented by speculative pre-execution and sandbox enforcement. See [§ Protection ring / commitment model](#protection-ring--three-tier-commitment-model) below for the mechanics of each ring, and `threat-model.md` §4.4 for the full adversarial analysis.

---

## Event sourcing model

Every action in a session produces an append-only event row. Events are never updated or deleted. The event log is the authoritative historical record: audit trail, replay source, and UI data layer.

```
Event {
    id          ULID        -- globally unique, time-sortable
    session_id  text
    actor_id    text        -- who caused this
    type        text        -- "message.posted", "approval.granted", etc.
    payload     JSONB       -- full serialized WsMessage (type-specific fields)
    seq         int8        -- monotonic per-session counter, no holes
    timestamp   timestamptz
}
```

The `seq` counter is incremented atomically inside each transaction (`UPDATE session_sequences SET next_seq = next_seq + 1 WHERE session_id = $1 RETURNING next_seq - 1`). Clients detect gaps on reconnect and request a fresh snapshot rather than replaying from a potentially stale position.

`seq` is a **per-session** counter — meaningless for ordering events across sessions. Cross-session views (the activity feed, cross-session linking — see below) order by `timestamp` instead.

---

## Snapshot projection

Session state lives at three layers that always agree:

```
EventLog (Postgres events table)
  Append-only. Every committed action is a row.
  Authoritative historical record. Never mutated.

SessionSnapshot (Postgres session_snapshots table)
  A single JSONB row per session: present state materialized
  from the EventLog via apply_event(). Updated atomically
  inside the same transaction as each event INSERT.
  Authoritative present state. Cold attach reads this — one
  query instead of five.

ArcSwap<Option<LiveSnapshot>> (in-process memory)
  Lock-free atomic pointer. Warm path for WS attach (O(1),
  no DB round-trip) and for policy reads inside vote handling.
  Rebuilt from session_snapshots on first attach after a
  process restart. Ephemeral — always reconstructible from
  the DB layers above.
```

`apply_event` is a pure function: `(SessionSnapshot, WsMessage) → SessionSnapshot`. It is the only place session state is mutated on this path. Every event write goes through the same primitive:

```
BEGIN TRANSACTION
  1. next_seq_in_tx   → monotonic sequence number, no holes
  2. append_in_tx     → event row (EventLog)
  3. upsert_in_tx     → updated snapshot JSONB (SessionSnapshot)
COMMIT
  4. ArcSwap.store    → hot-path cache updated
  5. broadcast()      → fan-out to connected WS clients
```

Nothing is broadcast before a durable commit. The snapshot is never ahead of the EventLog.

This is the primary, authoritative write path (`crates/server/src/ws.rs`), documented in full below. A second, independent implementation of the same event/state/effect triad exists in `crates/session` — see [§ The session crate: a partially-wired state machine](#the-session-crate-a-partially-wired-state-machine) for what it is and, honestly, how much of it is actually reachable today.

### Recovery semantics

On cold attach (process restart or first WS connect for a session), the server reads the `session_snapshots` row. If absent, it falls back to a five-query table scan to reconstruct state from raw tables. After any successful attach the ArcSwap cache is populated for subsequent warm attaches.

If a client detects a seq gap on reconnect, it closes and reconnects to receive a fresh snapshot rather than trying to replay from a stale position.

---

## ArcSwap cache

`SessionHub` holds an `ArcSwap<Option<LiveSnapshot>>` — a lock-free atomic pointer updated via `store()` after each committed transaction. Reads are `load_full()` + clone of the inner `Arc`, taking no locks.

This is the hot path for:
- WS attach: serve snapshot without a DB round-trip
- Policy evaluation inside vote handling: read `approval_policy` without a query
- Session status gating: read `SessionStatus` before dispatching commands

The ArcSwap is ephemeral and always reconstructible from Postgres. It is never written directly — only `stamp_append_snapshot` updates it, and only after `tx.commit()` succeeds.

Each live session also has its own isolated `SessionHub`, created on first WS connect and torn down with connection lifecycle (`DashMap<session_id, Arc<SessionHub>>`) — there is no shared, cross-session broadcast bus. This is the reason the cross-session activity feed and session-linking auto-observer grant (both below) are REST/polling-and-membership based rather than live-pushed: there is currently no fan-out primitive that spans sessions.

---

## Human authentication (OIDC)

Humans authenticate via OIDC (`crates/server/src/auth.rs`); agents never touch this path — they use the join-token / attach-token flow in the next section. The two are deliberately separate and must never be merged: **OIDC answers "who are you?" (identity). The cap DAG answers "what can you do?" (authorization).**

```
1. GET /auth/oidc/start
   PKCE pair (challenge+verifier) + CSRF state token generated; (verifier,
   nonce) stashed in AppState.oidc.pending keyed by state; 302 to provider.

2. Provider redirects: GET /auth/oidc/callback?code=...&state=...
   - state validated, single-use (DashMap::remove — replay returns 400)
   - code + PKCE verifier exchanged for an ID token
   - ID token signature + nonce verified (replay prevention)
   - (sub, provider) mapped to actor_id — creates the actor on first login
   - opaque sp_token issued into human_sessions (7-day TTL)
   - 302 to OIDC_FRONTEND_REDIRECT#sp_token=<token>

3. POST /auth/oidc/logout — revokes a single session token.
```

`sub` + `provider` together form the identity key (`google/alice` ≠ `github/alice`). `human_sessions.id` stores only the SHA-256 hash of the raw token — a DB dump never exposes bearer tokens. On an actor's first login, `sub_to_actor_id` also runs a one-time mailbox backfill (see [§ Mailbox](#mailbox--session-invites) below) so invites sent before the actor had an account are surfaced retroactively.

### Auth layering used throughout the REST API

| Helper | Credential | Used for |
|---|---|---|
| `require_sp_auth` | Bearer `sp_token` | Resolves a verified human identity; no membership check |
| `require_session_member(min_role)` | Bearer `sp_token` + membership | The default gate for session-scoped reads/writes — verified identity *and* sufficient role in *this* session |
| `require_active_membership` | Self-asserted `actor_id` + membership check | Endpoints agents call without a bearer token (e.g. artifact creation) — self-asserted identity is acceptable here because it's cross-checked against real membership, not trusted alone |
| `require_cap_auth` | `cap_id` (validated against `session_tokens`) | Agent-facing endpoints — not-found→401, wrong-session→403, expired/revoked→410; returns the cap's *own* actor_id, never a body-claimed one |

`require_session_member` also transparently satisfies access granted via cross-session linking — see [§ Session-to-session linking](#session-to-session-linking) — since that mechanism works by lazily provisioning a *real* membership row, which every one of these checks already understands with no special-casing.

---

## Agent credential model

When an agent attaches to a session, it needs to know which session it belongs to, which actor identity it holds, and which tools it's allowed to call. This is a single-use token exchange, not ambient/env-var credentials kept in sync by an operator.

A human in the UI clicks **Attach Agent** and fills in an agent ID, an optional filesystem path, and a TTL. The server issues a short-lived token via a random ULID stored in `session_tokens` with the session ID, actor ID, and a list of permitted tools baked in. The UI surfaces a ready-to-run launch command with the token embedded.

`solarplex-shim` (see next section) starts, sees `SOLARPLEX_TOKEN` in the environment, and immediately `POST /api/attach`s it. The server looks up the token, marks it used (so it can never be replayed), and returns the session ID, actor ID, permitted tools, and the sequence number the issuer was looking at when they issued it. The shim sets those values in memory and proceeds. The token is gone. Every subsequent call the shim makes is scoped to that session and actor — no ambient credentials checked per request, because all the credential logic happens once, at boot.

### Token lineage

Each token row carries `parent_cap` — a self-referential FK pointing at the token that minted it, forming a delegation DAG walkable with a recursive CTE:

```sql
WITH RECURSIVE lineage AS (
    SELECT * FROM session_tokens WHERE id = $1
    UNION ALL
    SELECT t.* FROM session_tokens t JOIN lineage l ON t.id = l.parent_cap
)
SELECT * FROM lineage ORDER BY observed_seq ASC;
```

`observed_seq` anchors each token to the event-log position its issuer saw at mint time. `cap_id` on every event produced by a cap-authenticated actor makes "which events came from this credential chain" a direct query.

---

## The agent execution stack: adapter / shim / guardian

Every agent-originated tool call passes through three separate OS processes before anything executes. **No single process holds both decision authority and execution capability** — a compromise of any one process alone is insufficient to cause unauthorized execution. This replaced an earlier single-process "sidecar" design; the crate directory is still named `crates/sidecar` for historical reasons, but it no longer builds a binary called that — see the table below.

| Process | Crate | Binary | Trust level | Can | Cannot |
|---|---|---|---|---|---|
| **Adapter** | `crates/sidecar` | `solarplex-adapter` | Untrusted relay | Proxy MCP JSON-RPC; observe tool call args; propose calls to the shim; inject Solarplex meta-tools; scan artifact content | Self-approve anything; reach the guardian; hold a session token |
| **Shim** | `crates/shim` | `solarplex-shim` | Trusted gatekeeper | Hold session token/cap; run the Ring-2 runahead scout; create approval requests; issue a `ProposalDecision`; spawn both other processes | Execute any command (no shell access); talk to the upstream MCP server directly |
| **Guardian** | `crates/guardian` | `solarplex-guardian` | Trusted executor | Spawn sandboxed subprocesses (bwrap + landlock + seccomp); carry out a `ProposalDecision` | Create or vote on approvals; hold or read a session token; talk to the adapter |

This is a **positional authority** model: the shim holds credentials but has no execution path; the guardian has an execution path but independently re-verifies every decision with the server before acting — it never trusts the shim's word for what was approved.

### Spawn tree vs. message flow

These are different graphs. **Shim is the process root** — it spawns both adapter and guardian as children (via Unix socketpairs created before `exec`, one end `dup2`'d to a well-known fd: **fd 3** for the shim↔adapter link, **fd 4** for shim↔guardian). *Possession of the inherited fd is the authority proof* — no listening socket to discover, no secret to steal, no `SO_PEERCRED` check needed, since the kernel guarantees only a direct descendant inherits an open fd. Both children set `O_CLOEXEC` on their authority fd immediately so sandboxed/upstream children can't inherit it in turn.

**Message flow** for a tool call is a straight line through that spawn tree, not the tree itself:

```
AI client
   │  MCP JSON-RPC
   ▼
solarplex-adapter                                      fd 3 (authority = fd possession)
   │  AdapterMessage::Propose(ProposalRequest)
   ▼
solarplex-shim ──── announces approval window ───────► server
   │  (scout runs in background during the human wait)
   │  ShimMessage::Decision(ProposalDecision)
   ▼
solarplex-adapter  (forwards upstream if granted; for solarplex_exec, waits on guardian first)
   .
   .  solarplex_exec only:
   ▼
solarplex-shim ── GuardianRequest{approval_id}  (NO command — guardian fetches it itself) ──► fd 4
   ▼
solarplex-guardian
   │  GET /api/approvals/:id  (X-Session-Id + X-Actor-Id; independent re-verification)
   ▼
server ── { decision, approved_command, declared_effects }   (3s timeout, fail-closed)
   │
   ▼
sandbox-entry: bwrap → landlock → seccomp → execvp     (see Ring 2, below)
   │
   ▼
guardian then runs a persistent single-reactor supervisor (io_uring, not
tokio) for the exec's whole lifetime, not a spawn-and-wait — brokers live
seccomp-notify grants as they happen (see Ring 2, below)
   │
   ▼
GuardianResponse{stdout, stderr, exit_code} ── back up through shim ── back to adapter ── to AI client
```

### No single-process compromise is sufficient

- **Compromised adapter** — can only *propose*; cannot self-approve, cannot reach the guardian, holds no token.
- **Compromised shim** — can forge `ProposalDecision{granted: true}`, but for `solarplex_exec` the guardian independently re-verifies with the server before executing; a forged decision with no matching `Approved` row server-side is refused. *(This protection is specific to the exec path — for non-exec tools, a compromised shim forging a grant is not independently caught, since no guardian is involved for those calls.)*
- **Compromised guardian** — can run arbitrary commands *inside its sandbox*, but cannot impersonate the shim to the adapter and cannot create or vote on approvals server-side. It's the only process with real execution power, so this is rated the highest-impact single-process compromise.
- **Full bypass** requires compromising the guardian *and* the server together, or the shim *and* the guardian together.
- **Open gap**: IMA appraisal / dm-verity tooling is built (`deploy/scripts/`, the `solarplex_binary_integrity` Ansible role) but not activated on any host — a host-level attacker who can swap the `solarplex-guardian` binary inherits its full authority, bypassing all of the above, until a given host actually runs the enable step. Guardian logs a warning naming this on every startup. See `threat-model.md` §4.6 and §11.1 for the full analysis.

### Artifact content scanning

Separately from the exec pipeline above, the adapter scans artifact **content** (not shell commands) for injection payloads on both a sync and async path:

- **Sync** (blocks nothing, runs inline): a 14-pattern Aho-Corasick automaton strips known prompt-injection phrases (`ignore previous instructions`, `system prompt:`, `<|im_start|>`, …) before the LLM sees content; a SHA-256 lookup against the server's reputation DB (`GET /api/artifact-hashes/:sha256`, 200ms timeout) prepends a `🚨 MALICIOUS` / `⚠ SUSPICIOUS` banner when the hash is already flagged.
- **Async** (background `tokio::spawn`, non-blocking): a 4-rule YARA-X scan (`prompt_injection`, `encoded_payload`, `shell_injection`, `data_exfil`) plus a TLSH fuzzy hash are computed and `POST`ed to `/api/artifact-hashes/scan-result`.
- **Server-side reputation** (`artifact_hashes`/`artifact_families` tables, migration 017): hashes seen fewer than 5 times always return `Unknown` regardless of family (prevalence gate, avoids single-occurrence false positives); family assignment prioritizes a YARA match, then TLSH-cluster proximity (distance < 50 on a 0–300 scale), then a manual `verdict_override`. A separate in-memory Count-Min Sketch scores content against the trigram distribution of everything seen so far, surfaced as `cms_score` — a signal for novel/anomalous patterns no YARA rule covers yet.

Full detail: `threat-model.md` §7.

---

## Cap revocation semantics

The cap DAG satisfies a monotone attenuation invariant: child permissions are always a strict subset-or-equal of parent permissions, computed as an intersection at mint time (`child_perms = requested ∩ parent.permissions`), enforced server-side, never accepted as a client assertion. This is a global condition with no exceptions — privilege escalation through delegation is structurally impossible.

Unlike traditional object-capability systems, Solarplex capabilities are stable references into the session object graph. They do not themselves confer authority. Authorization is derived from the current session state, policy, and approval chain, yielding signed receipts that are independently enforced by the runtime.

### Revocation is total over a stratum

A **stratum** is the set of all caps rooted at a given intermediate cap. Revoking an intermediate revokes the entire stratum simultaneously. There is no partial revocation that leaves some delegatees with stale authority — partial revocation would require abandoning the single epoch-write model for a per-cap revocation list, which destroys the O(1) check and reintroduces the state-management cost the epoch scheme was designed to avoid.

**A stratum is therefore the natural unit of co-revocation.** Choosing the delegation topology is choosing the revocation granularity. Agents whose authority may need to be revoked independently should be issued from separate intermediates at attach time. One agent attach ceremony = one intermediate cap = one independently revocable stratum. The expensive re-partition ceremony (below) is the exception path for when provisioning predictions were wrong, not the common case.

### Epoch-based authority check

Each stratum carries a monotone epoch counter keyed by the intermediate cap's ID, stored in Postgres and cached per-session in ArcSwap. Every cap validation reads the stratum epoch and checks that the cap's minted epoch matches:

```
cap.epoch == stratum.current_epoch   →  valid
cap.epoch != stratum.current_epoch   →  revoked, deny
```

Revocation is a single atomic epoch increment, cross-session — all sessions where the stratum holds live caps invalidate simultaneously.

**Staleness fence.** The ArcSwap cache is not the authority for epoch-sensitive checks. Cache staleness is bidirectional: a stale cache may accept a revoked cap *or* reject a newly minted valid cap (since epoch advances on revocation and new caps carry the new epoch). Both directions are wrong. Mutating dispatch paths re-read the stratum epoch from Postgres before committing. Read paths may use the cache. If the Postgres read fails, the action is denied (fail-closed). Documented propagation bound: revocation reaches all session caches within fan-out latency; during this window reads may reflect pre-revocation state, mutations do not.

### Drain-bounded liveness

Revocation blocks on open obligations — approval requests in `Pending` or `Claimed` state initiated under the stratum being revoked — up to the approval timeout TTL (the system's stated maximum acceptable authority latency). At expiry, the epoch advance and force-denial of all open obligations execute in a single transaction, attributed to the revoking principal:

```sql
BEGIN;
  UPDATE strata SET epoch = epoch + 1 WHERE root_cap_id = $1;
  UPDATE approvals
    SET state = 'denied',
        reason = 'stratum_revoked',
        revocation_event_id = $2
    WHERE issuing_stratum = $1
      AND state IN ('pending', 'claimed');
COMMIT;
```

The force-denial is a **consequence** of the epoch write, co-transactional with it — not a downstream effect, not an action taken under the dying authority, not blockable by the revocation target. Every force-denied approval carries the revocation event's ID, making "why was this denied" self-answering in the audit log.

The revocation emits `approval.revocation_interrupted { approval_id, revoked_stratum_id, re_requestable: bool }` for each force-denied obligation so surviving members can re-present the underlying need to the new stratum. Revocation is a guillotine on the obligation; it is not a guillotine on the work the obligation gated.

### Selective revocation via re-partition

If independent revocation of a subset of a stratum's delegatees is required:

1. **Mint** a new intermediate cap
2. **Re-derive** surviving delegatees under the new intermediate (monotone attenuation applies — new caps are permission-equal-or-less)
3. **Advance** the old intermediate's epoch (killing the old stratum, including the target)

The mint-before-advance ordering is mandatory: it ensures no outage window for surviving principals. The brief overlap where both old and new caps are valid is safe — monotone attenuation prevents any escalation during the window.

This re-partition is the escape hatch for when provisioning predictions were wrong. The prophylactic form: **provision one intermediate per independently-revocable principal** at attach time, so selective revocation never requires ceremony.

### Authority layer consistency model

The epoch mechanism is a linearizable authority register — a deliberate choice of consistency over availability at the authority plane. Every boundary condition resolves toward "preserve the invariant, pay in liveness or ceremony, bound the payment":

- **Drain** cost is bounded by an already-existing timeout (approval TTL)
- **Staleness** cost is fenced to reads; mutations pay one authoritative Postgres round-trip
- **Selective revocation** cost is pushed to provisioning time, not incident time

All three payments are bounded and explicit.

### ORB: typed cap addresses (`mcp_methods` / `execution_receipts`)

**ORB = Object Request Broker.** It restructures the agent tool-call trust boundary so authorization decisions live entirely server-side rather than trusting a separately-running process to execute what it claims it will. It is not a separate authorization system — it's the same cap DAG above, extended so `cap.permissions` holds typed method **addresses** (`"mcp.{server_slug}.{method_name}"`) instead of free-form tool-name strings, closing a TOCTOU gap where a compromised agent-side process could show a human safe args and then execute different ones.

```
solarplex-shim                                    server
   │                                                  │
   ├─ POST /sessions/:id/methods (register) ────────►│  mcp_methods: (session_id, address) → arg_schema, requires_approval
   │                                                  │
   ├─ POST /sessions/:id/invoke                      │  1. rate limit (60/min/cap)
   │    { cap_id, method, args } ────────────────────►│  2. cap validation (session, expiry, revocation, epoch)
   │                                                  │  3. method resolution
   │                                                  │  4. cap permission check (address in cap.permissions?)
   │                                                  │  5. standing policy check (auto-approve / always-deny patterns)
   │                                                  │  6a. requires_approval=false → issue receipt now
   │                                                  │  6b. requires_approval=true  → create approval (same
   │                                                  │      path the human-in-the-loop WS flow already uses),
   │                                                  │      issue a receipt bound to that approval_id
   │◄── { status: pending|approved, approval_id?, receipt_id } ┤
   │                                                  │
   │  (polls GET /approvals/:id/resolution if pending)│
   │                                                  │
   ├─ POST /sessions/:id/consume-receipt ────────────►│  atomic single-use UPDATE ... WHERE used_at IS NULL
   │◄── receipt.args (server-canonical) ───────────────┤  RETURNING ...  — double-consume → 410
```

The shim must execute the **receipt's** args, not its own copy — this is what closes the post-approval args-substitution gap. `execution_receipts` are single-use (`used_at` set atomically on consume) with a short TTL (30s auto-approved, 240s pending-approval).

---

## Protection ring / three-tier commitment model

The concrete mechanics behind the [three-ring table](#the-core-model) at the top of this document.

### Ring 0 / Tier 1 — declarative mutations, atomic CAS

Applies to: artifact content updates, context entries. Schema: `write_proposals` (migration 014).

```
POST /sessions/:id/invoke (as above) ──► receipt (args bound)
POST /sessions/:id/propose
    { receipt_id, effect_type, effect_payload, expected_hash_before, claimed_hash_after } ──► proposal_id
POST /sessions/:id/proposals/:pid/commit
    BEGIN
      SELECT artifact FOR UPDATE
      sha256(storage_ref) == expected_hash_before ?  → reject if not (CAS mismatch, 412)
      sha256(new_content) == claimed_hash_after   ?  → reject if not
      UPDATE artifact, mark committed
    COMMIT
```

`expected_hash_before` is the decisive value — the whole commit is one serializable Postgres transaction, so no concurrent write can interleave. `UNIQUE(receipt_id)` on `write_proposals` makes double-commit impossible. `artifact_patch` does a full hash-fenced content replace; `context_entry` is append-only (no hash fence — concurrent appends both legitimately succeed).

### Ring 1 / Tier 2 — filesystem writes, authorize-and-attest

Applies to: any tool writing to the agent's local filesystem. Schema: `file_write_attestations` (same migration).

POSIX provides no atomic compare-and-swap, for any party — this is not a server trust gap, it's a filesystem limitation. So Ring 1 can only detect divergence, not prevent it: the adapter reads the file's hash immediately before and after its own write and submits both, alongside the *approved* before/after hashes bound to the receipt, to `POST /sessions/:id/attest`. `hash_mismatch` is a Postgres `GENERATED ALWAYS` column (`observed_before ≠ approved_before OR actual_after ≠ approved_after`) — a permanently recorded, queryable security event (`GET /attestations?mismatch_only=true`), never deleted by the GC pass that otherwise ages out old attestation rows after 30 days. A mismatch means either the file was concurrently modified between approval and write, or the write produced different content than declared.

**What this does not prevent**: a compromised adapter can lie in the attestation — the hashes it reports are self-asserted, and the shim/server never independently re-read the file. Detection, not prevention, at this layer, for any implementation.

### Ring 2 / Tier 3 — shell commands, runahead scout + sandbox

Applies to: `solarplex_exec` and anything else whose effect isn't a declared content diff. State lives in `approval_requests`' `scout_manifest`/`declared_effects`/`execution_manifest`/`manifest_diverged` columns (migrations 016, 018) — no separate table, since the sandbox decision itself has no DB row.

**Runahead scout** (`solarplex-shim`, `scout.rs`): during the human approval wait — otherwise-idle latency — the shim speculatively runs the command under `strace -f` (Linux only; falls back to filesystem-snapshot-diff-only elsewhere), tracing `openat`/`unlinkat`/`renameat`/`connect`/`execve`, and PATCHes a `ScoutManifest` onto the approval **before the human votes**, so the approval UI can show predicted effects alongside the request. Same-path operations across the exec tree are unioned, not overwritten — the declared policy is the union of everything observed. This is the same idea as TOMOYO Linux's learning mode (observe first, enforce from the observation), applied at the shim layer instead of the kernel LSM layer. A bounded worker pool (`ScoutPool`) prevents one slow scout from blocking others; a full queue drops the job with a warning — the scout is a heuristic enhancement, and approval flow continues without it if dropped.

**Sandbox executor** (`solarplex-guardian`): once approved, the guardian executes inside a sandbox derived *exclusively* from the approved `DeclaredEffects` — no out-of-band configuration, no drift between what was approved and what's enforced:

1. **bwrap namespace** (Linux) — read-only rootfs, isolated `/tmp`, a writable bind-mount per declared file-effect path, `--unshare-net` unless network access was declared, always `--unshare-pid --unshare-ipc`.
2. **Landlock FS rules** (Linux ≥5.13, applied inside the namespace by `sandbox-entry`) — exactly the `AccessFs` flags each path's declared ops imply (create/write/delete/rename → distinct flag sets), not a blanket grant. This is the fine-grained layer; bwrap's bind-mount alone is coarse. Still the actual enforcement boundary for anything the live broker (below) doesn't specifically grant.
3. **Seccomp, two layers**: a classic BPF denylist (unchanged) that always blocks `ptrace`, `kexec_load`, `process_vm_readv/writev`, `perf_event_open`, `io_uring_setup/enter/register`, and conditionally blocks socket/connect/bind/listen/accept (no declared network) and execve (no declared subprocess) — plus a **live seccomp-notify broker**, layered on top with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, covering pathname-resolving syscalls (`openat`, `openat2`, `unlink`, `unlinkat`, `rename`, `renameat`, `renameat2`). For each sandboxed exec the guardian runs a persistent, single-reactor process supervisor (raw `io_uring`, not tokio — the trust boundary is between the guardian's own supervisory ring and the untrusted sandboxed child, kept structurally distinct rather than blurred through a shared async runtime) that watches the child's `pidfd`, the notify fd, and its stdout/stderr concurrently for the exec's whole lifetime. On each trapped syscall it resolves the path itself (TOCTOU-safe: read once from the tracee's memory, matched against `DeclaredEffects`, never re-resolved) and either **grants** it (`SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SEND` — the guardian opens the object in its own resolved context and injects the fd directly, so the tracee's own `openat2` never runs at all) or **continues** it (falls through to Landlock, backstopped exactly as before). Verified end-to-end on a real kernel — see `threat-model.md` §4.4/§11.1 for the two real bugs found and fixed getting here (a wrong seccomp flag bit value, and a read-only-vs-write-mode open mismatch).

On non-Linux or when `bwrap` is absent, execution fails closed by default (`SOLARPLEX_ALLOW_UNSANDBOXED=1` is an explicit, documented-as-unsafe-for-production dev escape hatch). `DeclaredEffects::default()` (used when the scout hasn't finished in time) is maximally restrictive — no file access beyond the read-only rootfs, no network, no subprocess — a deliberate fail-safe direction.

**Post-execution divergence check**: the guardian's result is compared against the scout's prediction (`ExecutionManifest`: missing writes = predicted-but-didn't-happen, unexpected writes = happened-but-wasn't-predicted). `manifest_diverged = true` is a permanent, queryable Ring-2 security event — it does **not** block or roll back execution, since the human approval decision is authoritative, not the heuristic scout. For `solarplex_exec` specifically, the guardian snapshots `DeclaredEffects`' paths itself, immediately before/after the sandboxed run — it has the real filesystem view the command actually touched, which the adapter (a different, downstream process) never did — and returns both snapshots in `GuardianResponse`, closing what used to be a structural no-op for exec calls specifically (empty pre/post snapshots, `manifest_diverged` never firing).

---

## Approval lifecycle

### Roles

| Role | Approve tool calls | Write artifacts | Delete artifacts | Transfer ownership | Manage members |
|---|---|---|---|---|---|
| Owner | Yes | Yes | Yes | Yes | Yes |
| Collaborator | Yes | Yes | Own only | No | No |
| Observer | No | No | No | No | No |
| Agent | — | Via tool calls | Via tool calls | No | No |

### ApprovalRequest schema

```
ApprovalRequest {
    id, session_id, actor_id,
    tool_name, arguments,
    state, votes,
    resolved_by, timeout_at, resolved_at,
    -- Ring-2 columns (migrations 016, 018) — NULL until a scout runs / execution completes
    scout_manifest, declared_effects, execution_manifest, manifest_diverged,
}
```

### ApprovalState transitions

```
Pending     → no votes yet
Claimed     → a human indicated they're reviewing (prevents racing)
Approved    → resolved affirmatively
Denied      → resolved negatively
Contested   → conflicting votes exist, owner resolution required
Expired     → timeout with no resolution
```

State transitions follow the session's `approval_policy`:

- **single_vote** (default): first vote resolves. Contested emerges if two votes conflict before one resolves.
- **majority**: requires >50% of eligible members (owners + collaborators).
- **unanimous**: all active eligible members must agree; any deny resolves as Denied.

The `votes` field is a JSONB map of `{ actor_id: "approve" | "deny" }`, queryable without parsing. The owner always has override authority from Contested. Every event constructed through this resolution path also carries the approval's `arguments` verbatim, both in the persisted event log and the live WS snapshot (`PendingApproval.arguments`) — added specifically so a client can render tool-specific detail (e.g. what's actually being proposed) rather than just a bare tool name.

**Caveat surfaced during a recent audit, not yet independently confirmed against the frontend**: the ORB path (previous section) can create *two* approval rows for a single gated call — one via `POST /invoke` carrying the real arguments (whose receipt is what's actually consumed on execution), and a second, separately-created row via the legacy approval endpoint that's what the shim actually polls for grant/deny, carrying only a placeholder reference to the first row's ID rather than the real arguments. If accurate, the record that's load-bearing for whether execution proceeds may not itself display the real command to the approving human (though the scout manifest, which does use the real args, still attaches to the right row). Needs a frontend-side check before being stated as settled fact; flagged here as a concrete follow-up.

---

## Mailbox & session invites

Two small, related mechanisms for pointing one actor or session at a fact owned by another, without copying it.

**Session invites** (`session_invites`, migration 019) — mint a link the same way a human is invited into a session: `POST /sessions/:id/invites` stages a role grant (+ optionally a cap request), redeemable once via `invites::redeem`'s atomic validate-and-consume `UPDATE ... WHERE redeemed_at IS NULL ... RETURNING`. The invite's own ULID `id` is the bearer token — no separate hash column, matching the pattern every other single-use token in this codebase uses.

**Mailbox** (`mailbox_routes`, migration 021) — a thin edge relation, `(mailbox_actor_id, entity_uri)`, pointing a receiver's mailbox at a sender-owned fact **by reference** (`EntityHandle::uri()`), never duplicating its content. Populated at invite-creation time (if the invitee's email already resolves to a known actor) and via a one-time backfill sweep on an actor's first login (for invites that arrived before they had an account). `GET /api/mailbox` resolves each stored URI back to the real object at read time.

**`EntityHandle`** (`crates/protocol/src/types.rs`) is the addressing scheme both of the above (and cross-session linking, next) build on — a closed, typed enum (`Session | Artifact | Actor | Context | Cap | Approval | Invite`) with `.uri()`/`.from_uri()`/`.entity_type()`/`.id()`, plus `permits_untrusted_dispatch()` as the hook point for gating what an OSC-8-clicked or `xdg-open`-dispatched reference from an untrusted source is allowed to do.

---

## Cross-session activity feed

`GET /api/activity` — recent events merged across every session the signed-in actor is a member of, ordered by wall-clock `timestamp` (never `seq`, which is per-session and meaningless across sessions). Deliberately polling (30s interval + refetch-on-focus), not live-pushed, for the same reason noted under [ArcSwap cache](#arcswap-cache): each session's broadcast stream is its own isolated channel, and there is no cross-session fan-out to tap into. Building a live-pushed version is a distinct, larger piece of infrastructure work, not attempted here.

Both this feed and the in-session Activity Log share one client-side, localStorage-persisted event-category filter (Messages / Approvals / Artifacts / Context / Presence / Tool calls / Session) so muting the `actor.joined`/`actor.detached` presence noise — typically the bulk of any active session's log — sticks everywhere rather than needing to be set per-view.

---

## Session-to-session linking

**The core idea: linking confers no new authority.** It renders the *union* of sessions the viewing actor already belongs to — each session's own membership, roles, and caps still govern everything inside it. A link is purely an authorization relationship (a row in `session_links`), not a data copy, not a new live-transport layer, and not a new permission grant beyond "you may now also become an Observer over there."

### Establishing a link

Two paths, converging on one canonically-ordered `session_links` row (`(session_a, session_b)` with `session_a < session_b` enforced by both a DB `CHECK` and the app layer, so an A↔B link can never exist as two distinct rows):

- **Mint-and-redeem** (`session_link_invites`, mirrors session invites exactly — the row's own ULID is the bearer token): `POST /sessions/:id/link-invites` (Collaborator+ in the source), `POST /link-invites/:id/redeem` (Collaborator+ in the *target*, atomic validate-and-consume, self-link rejected).
- **Admin fast path**: `POST /sessions/:a/link/:b` — no invite round trip when the same actor already holds Collaborator+ in *both* sessions. This is exactly the authority they could already exercise on each session alone, just without going through the other side.

Either admin can later mute (`visibility='muted'` — stops granting *new* access via the link without dissolving it) or unlink from their own side.

### What a link actually does: lazy, real membership provisioning

This is the entire mechanism, and it's deliberately reused: `db::sessions::require_membership_or_linked_access` (the shared fallback added to both the WS-attach membership check and `require_session_member`) first tries a normal membership check, and only on `NotFound` (never on `Unauthorized` since a real member below the required role is not eligible for this fallback) checks whether the requesting actor is a member of some other session linked to this one with `visibility='full'`. If so, it **auto-provisions a real Observer `session_memberships` row on the spot**, via the same `add_member` every other membership grant uses.

The auto-grant is capped at Observer regardless of the caller's role on the other side — linking can never be used to shop around a Collaborator+ gate. Because the result is a genuine membership row, **every other membership-gated code path in the system — WS live attach, REST reads, historical events, artifacts, approval visibility — already works correctly through it with no further special-casing.** There is no separate replay log, no event-mirroring pipeline, and no new durability story to build: `session_memberships`/`events`, both already in Postgres, are the entire "can I see what happened while I wasn't watching" answer, for free, because a linked-in Observer is now indistinguishable from any other Observer once the grant exists.

**Known v1 limitation**: muting a link stops new auto-grants but does not retroactively revoke Observer memberships already provisioned before the mute — there's no marker distinguishing "this Observer row came from a link" from "this Observer was genuinely invited," so a blanket revoke-on-mute would risk kicking a real invited Observer by mistake. Flagged explicitly rather than silently under-delivered.

### Visibility of the link itself, not just what it grants

A link's *existence* is only visible to a viewer who is a member of **both** endpoints — `list_visible_for_session` filters at the DB layer, not just in the UI, so Bob (a member of session A but not B) asking "what is A linked to?" gets back nothing about B: not B's session ID, not its name. Otherwise a much smaller but real version of the same leak would exist — a non-member learning a linked session's existence and name just by being a member of the *other* end. The mute/unlink endpoints extend the same principle to the write side: attempting to act on a link you're not an admin of either side of returns an indistinguishable 404, not a 403 that would itself confirm the link exists (same anti-enumeration posture already used by `mailbox::mark_seen`/`descriptors::resolve`).

### The workspace UI

`/sessions/:id/sync` — a desktop of session "panes," each backed by its own genuinely independent live WS connection (the same `useSession` hook the main session page uses, pointed at a different `session_id`) rather than a read-only summary. Opening a linked session as a pane is what triggers the lazy membership auto-grant above; from then on it behaves exactly like being in that session directly — live messages, artifacts, and approvals, not a cache. Panes are freely draggable and resizable (framer-motion `MotionValue`s for position, hand-built 8-direction resize handles rather than relying on native CSS `resize`, which only ever exposes a single bottom-right handle in any browser) and pop in/out with a plain CSS-transition animation rather than framer-motion's `AnimatePresence` — a deliberate choice, not an oversight: JS-driven exit animations were found to get stuck mid-transition and never resolve in at least one constrained test environment, where a browser-native CSS transition (no separate animation state machine to desync) does not. Pane position/size is `localStorage`-only, keyed per home session, and never sent to the backend — "workspace layout is personal," an explicit product decision.

---

## WebSocket protocol

Three transport types, all versioned:

```jsonc
{ "protocol_version": 1, "id": "...", "type": "...", ...fields }
```

**Commands** (client → server):
```
approval.grant      approval.deny          approval.claim
approval.cancel     approval.delegate      approval.dispute
ownership.transfer  message.post
context.entry.add   context.entry.resolve
```

**Events** (broadcast to all session members, written to event log):
```
tool.call.requested     tool.call.executed      tool.call.blocked
approval.requested      approval.claimed        approval.granted
approval.denied         approval.contested      approval.timed_out
approval.cancelled      approval.delegated      approval.disputed
actor.joined            actor.detached          ownership.transferred
artifact.created        artifact.updated        artifact.deleted
agent.status.changed    session.status.changed  message.posted
context.entry.added     context.entry.resolved
```

**Snapshots** (unicast on attach, not written to event log):
```jsonc
{
  "protocol_version": 1,
  "type": "session.snapshot",
  "session_id": "...",
  "seq": 4283,
  "state": {
    "owner": "alice",
    "status": "active",
    "members": [...],
    "pending_approvals": [...],   // each now carries `arguments` — see Approval lifecycle
    "artifacts": [...],
    "context": [...]
  }
}
```

On attach, the server sends a snapshot at the current `seq`. After that, events arrive with `seq > snapshot.seq`. The frontend also fetches historical events via `GET /sessions/:id/events?limit=500` after the first snapshot to populate the activity log and message history — the snapshot provides present state but not the full event stream.

A server-wide `PgListener` (`crates/server/src/notifier.rs`) subscribes to Postgres `LISTEN "session_events"`, payload `"{session_id}:{seq}:{replica_id}"`. This is now full **cross-replica event delivery**, not just a wakeup nudge: on notify, the listening replica fetches the actual event row, reconstructs the exact `WsMessage` that was originally broadcast, and replays it through the same `apply_event` + `store_and_broadcast` pipeline same-replica delivery already uses — a client attached to a different replica than the one that handled a given write sees it live, exactly as if its own replica had made the write. (The notify is skipped for the replica that made the write in the first place — `emit_to_session` already broadcast it synchronously in the same request; re-delivering here would double-count it.) `session_task.rs`'s `PersistPlan` write path (see below) fires on the same, correct channel and payload shape — the two write paths that used to diverge (a stale channel name nothing listened on) now agree.

---

## The session crate: a partially-wired state machine

`crates/session` is a second, independent, zero-runtime-dependency implementation of the same event/state/effect triad already described above (pure `transition(state, memory, event) -> (state', memory', Vec<Effect>)`, no tokio/axum/sqlx — chosen specifically so it's proptest-friendly; see `crates/session/tests/proptest_invariants.rs`, 17+ named invariants). This is designed to be *the* source of truth for session execution and runtime semantics — `session_task.rs`'s own doc comment names the target end state explicitly: "machine owns ALL session_events writes." That end state isn't reached yet, but a wiring pass has closed most of the input-coverage and correctness gaps; what remains is narrower and more specific than it looks from the type signatures alone.

**What's real today**: `session_task.rs` spawns one dedicated tokio task per live session (`AppState::get_or_create_session_task`, `state.rs:319`). On spawn, `replay_history()` (`session_task.rs:242`) loads a session's full event log (`db::events::list`) and folds it through `transition()` as `InboundEvent::Replayed` before the task accepts live input — a freshly-spawned or post-restart task's memory reflects real history, not just what it personally observes going forward (`transition()` itself debug-asserts a `Replayed` transition never produces a `Persist` effect, so this fold is safe by construction; `SetTimer`/`CancelTimer`/`Broadcast` effects still fire for real on replay, e.g. `BundleDeferred` re-arms a timer for its remaining wall-clock duration). `ws.rs` and `routes/sessions.rs` together now feed the task translated events for essentially every live event kind they handle — actor connect/disconnect, vote cast, approval create/claim/cancel/delegate/dispute, ownership transfer, session pause/resume/archive, message post, context add/resolve, artifact create/update/delete. (`tool.call.*` stays unbridged; it's dead/aspirational, never constructed anywhere in the codebase, and out of scope.)

Once inside, `is_machine_autonomous()` (`session_task.rs:457`) decides who owns the write. For events `ws.rs` never persisted itself — `ApprovalExpired`, `ApprovalInterrupted`, `AgentAttached`/`AgentDetached`, and the entire saga and policy sub-algebras — the machine is the **real, sole writer**, via `real_persist` → `db::persist_plan::PersistPlan` → Postgres, updating `hub.snapshot` (the ArcSwap) directly, and broadcasting a correctly-typed `WsPayload` (`session_broadcast::to_ws_payload`, a dedicated translation module — see below) instead of a generic ping. Every event kind added by the wiring pass — ownership transfer, pause/resume/archive, approval claim/cancel/delegate/dispute, message post, context add/resolve, artifact create/update/delete — is deliberately left **shadow-persisted** instead: `ws.rs`/`routes/sessions.rs` remain the writer of record, and the machine's own copy (drawing a real seq from the same `session_sequences` counter `real_persist` uses, but writing no Postgres row) exists purely to keep its bookkeeping — `eligible_approvers`, timers, vote tallies, `memory.artifacts`/`memory.context` — correct. This is a scope boundary, not an oversight: REST endpoints for artifacts/context need a synchronous return value (the created/updated object), and the machine's mailbox is fire-and-forget with no reply-channel mechanism; the WS-only kinds (message/claim/cancel/delegate/dispute) have no such blocker and could be cut over to real-persist next, but were left shadow for consistency with the rest of the pass rather than cut over ad hoc.

The effect interpreter (`run_effects`) is complete: every `Effect` variant (`Persist`/`Send`/`Broadcast`/`Forward`/`SetTimer`/`CancelTimer`/`CloseConnection`/`PersistSnapshot`/`Bundle`/`BundleDeliver`) has a real, working handler — including `Effect::Bundle` → `route_bundle()` (`session_task.rs:754`) → a genuine `reflector.append()` call plus an attempted live delivery to the target session's mailbox. The reflector now has a real producer, not just a consumer: `live_saga_begin` and the `Advance`/`Abort` arms of `live_saga_ack` (`transition.rs`) construct `Effect::Bundle` — previously `Effect::Forward`, which reached the target session's mailbox directly but bypassed the reflector's durability and replay guarantees entirely — with a deterministically-constructed `bundle_id` (`{saga_id}:{idx}:step`/`:comp`; `crates/session` has no `ulid`/`rand` dependency by design, so IDs here are always derived, never generated).

**`crates/server/src/session_broadcast.rs`** is new supporting infrastructure from this pass: a `SessionEvent → WsPayload` translation layer, called only from `real_persist` (shadow-persisted events already get a correctly-typed broadcast from whichever `ws.rs`/`routes/` handler is still their authoritative writer, so adding one here too would just double harmless-but-pointless broadcast traffic). It returns `None` for the handful of `SessionEvent` kinds with no defined `WsPayload` shape yet (`ApprovalInterrupted`, the saga/bundle/policy sub-algebras) — those callers fall back to the generic `session_updated` ping, matching prior behavior for those kinds exactly.

**The actual gaps that remain**, verified directly against source:

1. **Write-ownership isn't fully flipped for the newly-bridged kinds.** They're all visible to the machine now, but `is_machine_autonomous()` still only returns true for the original four categories (approval-lifecycle timer/disconnect events, sidecar lifecycle, saga sub-algebra, policy sub-algebra) — unchanged by this pass. Closing this the rest of the way needs a reply-channel mechanism for the mailbox before REST handlers (artifacts, context) can safely depend on the machine's write for their response; the WS-only kinds could flip sooner since they have no such dependency. For the same-process case (today's architecture — one `solarplex-server` binary, session tasks live in an in-memory `AppState.sessions: DashMap`), a plain `tokio::sync::oneshot` threaded through the mailbox message is the natural reply channel: no Postgres round-trip, no payload-size limit, no missed-notification edge case. Postgres `LISTEN`/`NOTIFY` (already used server-wide in `notifier.rs` for the WS-nudge path) would become the right tool specifically if a REST request could land on a *different* server process than the one holding the target session's task — i.e. it solves cross-process delivery, not the reply-channel problem itself, and isn't needed unless/until this runs as multiple replicas with session-task affinity (no evidence today that it does — single-process, NUMA-aware within that one process, not horizontally distributed). If it's ever adopted, `NOTIFY`'s ~8000-byte payload cap means it should carry an ID to fetch by, not the full response inline, and still needs a timeout+poll fallback since `NOTIFY` has no delivery guarantee across a dropped listening connection.
2. **`SessionArena`**'s lifecycle is wired into `session_task.rs` (reset on `SagaTerminated`), but its allocation methods (`alloc_str`, `alloc_slice_copy`, `BumpWriter`) are never called — the saga hot path doesn't use the arena for anything yet beyond resetting it.

None of this is broken — the tests pass (pure proptests plus a live-Postgres integration suite in `session_task.rs`'s own test module, exercising real actors/sessions/broadcast hub rather than mocks), the types are sound, and both the executor side and the input-coverage side are now substantially wired. [Session-to-session linking](#session-to-session-linking) — the actual, shipped cross-session mechanism — still deliberately routes around all of this and works through Postgres membership rows instead. That remains an explicit v1 scope decision, not a judgment that this machinery isn't needed — see the TODO below.

---

## CLI — `sp`

Every entity in Solarplex has a canonical text address:

```
session/01KTWXXX          artifact/01KTWYYY
approval/01KTWZZZ         cap/01KTWAAA
actor/alice                invite/01KTWBBB
```

The `sp` binary treats these as routable references. Any address can be passed directly as a command:

```fish
sp artifact/01KTWYYY          # → sp artifact get 01KTWYYY
sp session/01KTWXXX           # → sp session inspect 01KTWXXX
sp actor/alice                # → sp actor show alice
sp 01KTWYYY                   # bare ULID — resolved by type heuristic + API fallback
```

### Dispatch layer

`sp plumb run <text>` routes any text through a ranked ruleset — builtin rules first, then `~/.config/solarplex/plumb.toml` for user overrides. Rules are regex patterns with capture groups:

```toml
[[rule]]
pattern = "^artifact/([0-9A-HJKMNP-TV-Za-z]+)"
action  = "sp artifact get {1}"
```

Rules are checked in order; first match wins. Unknown references fall through to `xdg-open`. User rules in `plumb.toml` are prepended, so they override builtins. `invite/<id>` resolves to opening `{SOLARPLEX_UI}/invite/{id}` in a browser, matching the `EntityHandle::Invite` variant.

### Terminal integration

All CLI output uses the `solarplex:entity/id` URI scheme for OSC-8 hyperlinks. In WezTerm:

- **Click** any printed reference → `sp plumb run` executes in the current pane (the command appears at the prompt and runs)
- **Alt+Enter** → plumbs the selected text or the word under the cursor
- **Ctrl+Shift+↑/↓** → jumps between prompts (requires OSC-133 shell integration, emitted by the fish adapter)
- **Tab title** → shows the first 8 chars of the attached session ULID

The fish shell adapter (`shell/solarplex.fish`) wraps every command with session tracking events (`shell.command.started`, `shell.command.completed`) and emits OSC-133 semantic marks so WezTerm understands the prompt/command/output boundary.

### URI scheme

`solarplex:entity/id` is registered as a system URI handler (`sp _install_uri_handler` on Linux, Windows registry on Windows). This makes references clickable outside the terminal — from a browser, document, or other application — routing back to `sp plumb`.

### Participation and object creation

The CLI is a full read-write interface to the session, not just an inspection tool. The same object graph traversable by clicking printed references is also writable from the terminal:

- `sp session feed` — live IRC-style feed: shows recent events on entry, accepts typed messages posted to the session, polls for new events in the background. Equivalent to the web frontend's message panel without the browser.
- `sp session workspace` — splits WezTerm into a feed pane (interactive) and an auto-refreshing inspect pane. Additional panes (`--panes inspect,feed,artifacts,context`) are opt-in.
- `sp context add [kind] <text>` — appends a typed epistemic entry (fact, hypothesis, decision, question, constraint) to the session context. `sp context ls` lists entries as clickable references; `sp context show <id>` displays a single entry.
- `sp artifact create --name <name> --file <path>` — creates an artifact from a local file. `sp artifact get <id> --save <path>` downloads artifact content to disk, with a 60-line inline preview for text content.

The web frontend and CLI are peers over the same REST/WS API. Events posted from the CLI appear immediately in the frontend's timeline and vice versa.

## Prior art and design lineage

The list of inspirations is short, and is mostly written to document lineage of specific architectural decisions within the Solarplex suite. These are included to acknowledge specific design influences as opposed to an attempt to recreate or synthesize any of the below projects.

| Lineage | Solarplex influence |
|---|---|
| Object-capability systems (E, Capsicum) | Explicit authority, attenuation, delegation and revocation |
| Smalltalk | Live, inspectable object environment and message-oriented interaction |
| Plan 9 | Addressable objects, navigable shell tooling, namespace composition |
| Erlang | Durable session workflows and fault-tolerant isolation |
---

## Secrets management

Solarplex's *static* infrastructure secrets — `DATABASE_URL`, `OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET`, the complete list; everything else the app uses (session tokens, join tokens, caps) is runtime-issued and self-rotating, out of scope here — go through a separate, small, 5-layer pipeline of their own, decoupled from everything above:

1. **Ratchet** (`crates/secrets-ratchet`) — forward-secret rotation chain, `state_{N+1} = HKDF(state_N || fresh_random)`, domain-separated per-credential derivation, explicit zeroization. Pure and I/O-free by design: no opinion on encryption, systemd, Ansible, or Postgres.
2. **Store** (`crates/secrets-store`) — multi-recipient `age` encryption of the credential bundle the ratchet rotates. Identity-agnostic (a software X25519 key in a test, a hardware-backed age plugin — YubiKey, TPM — in production), since both satisfy the same `age::Recipient`/`age::Identity` traits.
3. **Delivery** (`crates/secrets-cli`) — the one binary that actually touches disk: `init`/`encrypt`/`rotate`/`decrypt` subcommands, plus a separate `encrypt-bytes`/`decrypt-bytes` pair for secrets that want the same pipeline but don't fit the fixed 3-field bundle shape (e.g. backup object-store credentials, which rotate on the storage provider's own schedule). `decrypt` runs on the target host as systemd `ExecStartPre`, turning `secrets.age` into the `EnvironmentFile=` systemd reads. Identities are always passed via `--*-env` environment variables, never bare CLI args, so they never land in `ps` or shell history.

Full adversarial analysis — what this design protects against, what it doesn't, and verification performed — lives in `threat-model.md` §13, which this section defers to rather than duplicates, matching this document's convention throughout.

---

## Repo structure

13 workspace crates. Binary name is noted wherever it differs from the crate directory name (`sidecar` → `solarplex-adapter` is the one that matters most; see [The agent execution stack](#the-agent-execution-stack-adapter--shim--guardian)).

```
solarplex/
├── Cargo.toml                   # workspace: protocol, db, server, sidecar, cli, session, guardian, shim,
│                                 #            splx-ir, intent, secrets-ratchet, secrets-store, secrets-cli
├── .env.example
├── migrations/                   # 26 migrations; grouped by era below, not exhaustively listed
│   ├── 001_initial.sql .. 008_cap_lineage.sql      # core schema, snapshots, attach tokens, cap lineage
│   ├── 009_human_sessions.sql                       # OIDC sp_token storage
│   ├── 010_versioned_snapshots.sql .. 013_authority_transfer.sql
│   ├── 014_write_proposals.sql                      # Tier 1/2: write_proposals, file_write_attestations
│   ├── 015_security_hardening.sql
│   ├── 016_scout_manifests.sql, 018_ring2_sandbox.sql  # Ring-2: scout_manifest/declared_effects/execution_manifest columns on approval_requests
│   ├── 017_artifact_reputation.sql                  # artifact_hashes, artifact_families
│   ├── 019_session_invites.sql, 020_actor_descriptors.sql, 021_mailbox_routes.sql
│   ├── 022_session_object_refs.sql                  # ← superseded, see 024
│   ├── 023_session_links.sql                        # session_links, session_link_invites
│   ├── 024_drop_session_object_refs.sql              # removes 022's table — one cross-session mechanism, not two
│   ├── 025_session_link_invites_cascade.sql
│   └── 026_seed_system_actor.sql                     # "system" actor row — FK target for machine-generated events' actor_id
├── crates/
│   ├── protocol/                # shared types, zero runtime deps
│   │   └── src/{lib.rs, types.rs (EntityHandle, MemberRole, ApprovalState, SessionSnapshot, …),
│   │             messages.rs (WsMessage/WsPayload), effects.rs (Ring 0/1/2 type system), ipc.rs (adapter/shim/guardian wire protocol)}
│   ├── db/                      # sqlx repositories, no HTTP — one file per aggregate
│   │   └── src/{pool, actors, sessions, events, approvals, artifacts, snapshots, tokens,
│   │             human_sessions, invites, mailbox, descriptors, session_links,       # auth/social layer
│   │             epochs, authority_arena, methods, receipts, proposals,               # authority/ORB/ring layer
│   │             authority_import,                                                    # sp-dsl wire-format import, see below
│   │             artifact_reputation, persist_plan}
│   ├── session/                 # pure state machine (transition/state/memory/events/effects/saga/arena) — see
│   │   └── src/{lib, state, memory, events, inbound, effects, transition, saga, arena}   # "The session crate" section: partially wired, see there for exactly how much
│   ├── server/                  # Axum binary
│   │   └── src/{main, lib, state (AppState/SessionHub/ArcSwap), auth (OIDC), authz (role predicates),
│   │             ws (primary event/snapshot commit path), session_task (per-session actor, session-crate bridge, cold-start replay),
│   │             session_broadcast (SessionEvent → typed WsPayload, real-persist only),
│   │             reflector (bundle producer: saga dispatch; consumer: route_bundle in session_task), notifier (PgListener), gc (4 hourly retention jobs), numa (forward-looking)}
│   │       └── routes/{sessions, activity, approvals, actors, approval_policies, artifact_hashes,
│   │                    auth_query, descriptors, epoch, invites, invoke (ORB), mailbox,
│   │                    proposals (Ring 0/1), session_links}
│   ├── sidecar/                 # binary: solarplex-adapter — untrusted MCP relay
│   │   └── src/{main, proxy (MCP proxy + meta-tools), artifact_scan, yara_scan}
│   ├── shim/                    # binary: solarplex-shim — trusted gatekeeper, spawns adapter + guardian
│   │   └── src/{main, approval (decision tree), policy, scout (Ring-2 runahead), session (server HTTP client),
│   │             sealed (mmap/mprotect(PROT_READ)/mseal — process-lifetime sealing of the shim's own
│   │             cap-node identity and standing-policy cache against in-process tampering)}
│   ├── guardian/                 # binary: solarplex-guardian — trusted sandboxed executor
│   │   └── src/{main, verify (independent server re-check), executor (bwrap), sandbox_entry (landlock+seccomp),
│   │             notify (per-exec io_uring reactor supervisor: pidfd/notify-fd/stdout/stderr, ADDFD/CONTINUE
│   │             dispatch), seccomp_ffi (raw seccomp-notify FFI — structs/ioctls/BPF, hand-rolled), fd_passing
│   │             (SCM_RIGHTS fd handoff), rootfs (opt-in minimal OCI-derived sandbox rootfs, in place of a
│   │             read-only host bind, closing a low-severity info-disclosure surface)}
│   │       └── bin/notify_minimal_probe.rs   # standalone io_uring-free reproduction harness for the
│   │                                          # seccomp-notify mechanism, built for live-kernel debugging
│   ├── cli/                     # binary: sp
│   │   └── src/{main, config, output (OSC-8/OSC-133), client}
│   │       └── cmd/{session, artifact, approval, cap, actor, context, plumb, shell}
│   ├── splx-ir/                 # Rust reader for sp-dsl's authority-dsl wire format (s-expressions) —
│   │   │                         # deserialize only, does not re-verify or re-implement lattice logic;
│   │   │                         # see docs/dsl-guide.md's "Rust Consumers". Not wired into guardian/session
│   │   │                         # yet (deliberate, deferred) — db::authority_import (above) is the other,
│   │   │                         # already-live consumer, exposed at `POST /sessions/:id/authority`.
│   │   └── src/{lib, ir, algebra, operational, parse, resource, saga}
│   ├── intent/                  # deterministic (non-LLM) parser: governance chat/palette text ("pause this
│   │   │                         # session") → structured Intent. Grammar (xre) → NFA compile → match. Wired
│   │   │                         # into `GET /intent/parse` (crates/server); every existing authz check still
│   │   │                         # runs on the parsed result — this crate has no opinion on who's allowed to
│   │   │                         # do what, only on what a human typed. Parse failure always falls back to
│   │   │                         # normal chat/fuzzy-palette behavior, never guesses.
│   │   └── src/{lib, intent, compile, matcher, slots, vocab, error}
│   ├── secrets-ratchet/         # layer 1/5 of static-secret rotation (DATABASE_URL, OIDC_CLIENT_ID/SECRET —
│   │   │                         # the complete list; everything else is runtime-issued and self-rotating).
│   │   │                         # Pure, I/O-free: state_{N+1} = HKDF(state_N || fresh_random) + explicit
│   │   │                         # zeroization. See threat-model.md §13 for the full 5-layer design.
│   │   └── src/{lib, state, entropy}
│   ├── secrets-store/           # layers 2/3: multi-recipient `age` encryption of the credential bundle
│   │   │                         # secrets-ratchet rotates. Identity-agnostic (software key or hardware —
│   │   │                         # YubiKey/TPM — via age::Recipient/Identity traits); never touches disk itself.
│   │   └── src/{lib, bundle, store, error}
│   └── secrets-cli/             # layer 4: the one binary that touches disk on the ratchet/store's behalf —
│       │                         # init/encrypt/rotate/decrypt subcommands; `decrypt` runs on the target
│       │                         # host as systemd `ExecStartPre`.
│       └── src/main.rs
├── sp-dsl/                      # the Lisp side of the authority DSL (Common Lisp) — see docs/dsl-guide.md
├── shell/{solarplex.fish, wezterm.lua}
└── frontend/                    # Next.js app
    ├── app/
    │   ├── page.tsx                     # session list
    │   ├── activity/page.tsx            # cross-session activity feed (polling, category filter)
    │   ├── inbox/page.tsx                # mailbox
    │   ├── invite/[id]/page.tsx
    │   ├── cli-auth/page.tsx
    │   ├── sessions/[id]/page.tsx (main session workspace; "new session" is NewSessionDrawer, a slide-over, not a route)
    │   ├── sessions/[id]/sync/page.tsx    # cross-session linking workspace (draggable panes)
    │   └── agents/, search/, settings/, team/   # all implemented; agents/ and team/ are read-only
    │                                             # co-membership-scoped directories (human vs. agent actors),
    │                                             # not yet the full provider/policy/role-management scope
    │                                             # originally sketched for them
    ├── components/                       # ~28 files; a few (ApprovalPanel, ArtifactDrawer, SessionGraph,
    │   │                                  # SessionHeader, VoiceMemoPlayer) are currently unimported dead code,
    │   │                                  # left as-is rather than pretended-live or silently deleted
    │   ├── AppShell.tsx, AppNav.tsx        # global nav shell, mailbox badge
    │   ├── StatusPanel.tsx                 # session sidebar: lifecycle, owner, members, Session Sync entry point
    │   ├── SyncWorkspace.tsx               # cross-session linking workspace — draggable/resizable panes
    │   ├── Timeline.tsx, Messages.tsx, ArtifactsTab.tsx, ContextTab.tsx, Whiteboard.tsx, NeedsAction.tsx
    │   ├── EventTypeFilterBar.tsx          # shared activity-category filter (Timeline + Activity page)
    │   ├── OnboardingNameModal.tsx, GlobalCommandPalette.tsx, SessionMinimap.tsx
    │   └── HandoffSummary.tsx, MarkdownContent.tsx, OwnershipPanel.tsx, RelativeTime.tsx, SolarplexLogo.tsx, SessionSkeleton.tsx
    └── lib/
        ├── auth.ts                        # sp_token storage/retrieval, OIDC redirect helpers
        ├── ws.ts                          # useSession() hook — snapshot + history replay + incremental projection
        ├── sessions.ts, sessionLinks.ts, mailbox.ts, activity.ts, eventFilter.ts
        ├── types.ts                        # TypeScript mirror of protocol types
        └── env.ts, actorOverride.ts
```

---

## v1 TODOs

Genuinely open items, audited against current code — several items from earlier drafts of this document are done and have been folded into the sections above rather than listed here (human OIDC auth, mailbox, cross-session activity feed, cross-session linking).

### Escalation chain routing

The timeout sweeper transitions approvals directly to `Expired`. It should walk the `escalation_order` chain in `session_memberships`, notify the next actor, and only expire if the chain is exhausted.

### ORB dual-approval-row behavior needs frontend verification

See the caveat under [Approval lifecycle](#approval-lifecycle) — confirm whether the approval record a human actually votes on in the ORB path displays the real command, or a placeholder reference to a second row.

### IMA appraisal + dm-verity (tooling built, not activated on any host)

Binary integrity verification for the three-process stack — see [The agent execution stack](#the-agent-execution-stack-adapter--shim--guardian) and `threat-model.md` §4.6/§11.1. Tooling exists (`deploy/scripts/`, the `solarplex_binary_integrity` Ansible role); activation is a one-time, one-host-at-a-time operator action not yet run against a real production host. Until it has been, guardian binary substitution is mitigated only by OS-level file permissions.

### Sidecar policy refresh without restart

The shim fetches `Policy.server_policies` from the session server once, at attach time (`crates/shim/src/main.rs`) — session-owner-configured standing policy is respected on a fresh attach. What's still missing: it's never refreshed after that, so a policy change mid-session needs a shim restart to take effect. Add a refresh on policy-update events.

### Whiteboard real-time sync

The whiteboard currently persists via the artifact API (save/load on demand). Real-time multi-user sync requires broadcasting Excalidraw store diffs over the WS event stream as `whiteboard.patch` events.

### Fine-grained cross-session link redaction

Session-to-session linking is currently all-or-nothing at Observer level (or muted). Per-category redaction (e.g. share messages but not artifacts) is a real, deferred feature, not an oversight.

### Artifact content storage

`storage_ref` currently stores inline content as a TEXT column. Large artifacts (whiteboard JSON, code diffs, generated reports) should reference a blob store (S3, R2, or local filesystem) rather than being embedded in Postgres rows.

### Agent config parsing

The `config` JSONB on the `actors` table has fields for `tool_policy` and `approval_policy`, but the server currently ignores them — the session-level `approval_policy` is the only thing evaluated. Per-agent policy override is designed but not wired.

### Contested owner notification

When an approval transitions to `Contested`, the owner should receive a targeted signal (directed WS message or push notification) since they're the only one who can resolve it.

### Docker / deployment

No Dockerfile or compose file yet. A minimal setup:
```
docker-compose.yml:
  - postgres
  - solarplex-server (compiled Rust binary)
  - solarplex-frontend (Next.js)
```
Adapter/shim/guardian are per-agent and deployed alongside the agent runtime, not as a central service.

---

## Design decisions

**Why the three-process split (adapter/shim/guardian) over one sidecar?** A single process that both decides "is this approved?" and has the power to execute is one compromise away from full bypass. Splitting decision authority (shim), relay (adapter), and execution (guardian) across separate OS processes with fd-possession-based IPC means a compromise of any one alone is insufficient — see [The agent execution stack](#the-agent-execution-stack-adapter--shim--guardian).

**Why a runahead scout instead of just trusting the declared tool args?** Shell commands are opaque at the primitive level — `run ./deploy.sh` isn't a declared content diff that can be hash-fenced the way an artifact patch can. Speculatively executing during the otherwise-idle human-approval wait and observing real behavior turns an opaque command into a concrete, sandbox-enforceable allow-list, at the cost of the scout being a heuristic (it can be dropped under load with no correctness impact — approval flow continues without it).

**Why does session-to-session linking grant real membership instead of building a live cross-session transport?** The alternative (mirroring events between sessions, a new fan-out bus, a persisted reflector) is a substantially larger and riskier piece of infrastructure, and a real chunk of that infrastructure (the reflector, the effect interpreter, the saga protocol) already exists, further along than it first looks. Auto-provisioning a real, capped-at-Observer membership row reuses every existing membership-gated code path for free and needed exactly one new function — a smaller, safer v1 answer to "let a user see two sessions at once" than wiring the session crate all the way through would have been. Revisiting this once the session crate is the actual runtime source of truth is a natural follow-up, not a dead end.

**Why not a central MCP proxy?** A central proxy sits in the LLM inference path, owns the failure surface for every tool call across all agents, and becomes a bottleneck. The per-agent adapter/shim/guardian stack keeps the session server a pure event coordinator handling approval signals and event fan-out, not tool execution.

**Why an append-only event log?** Append-only gives you audit, replay, and debugging for free. The `approval_requests` table is a materialized view over the event log for query efficiency — you get both. The event log is never updated or deleted in v1.

**Why ULID over UUID?** ULIDs are time-sortable by construction. No secondary sort on timestamp needed for log replay.

**Why not CRDTs for session state?** The session is server-mediated — no offline-first requirement. Server-authoritative state with a per-session sequence counter is simpler and sufficient. CRDTs (Automerge, Yjs) are worth revisiting for collaborative artifact editing and real-time whiteboard sync, where two humans editing simultaneously is a real use case. That's a v2 concern.

**Why cooperative trust boundary over pure enforcement?** Solarplex's goal is joint human supervision, not control. The threat model is honest agents operating within a multi-stakeholder team, not adversarial agents, which is also why the three-process split and Ring-2 sandbox exist: cooperative trust doesn't mean unverified trust.

**Is this just Slack with agents?** Solarplex is not a chat application with agents attached. Messages are only one projection of a session. The primary object remains the session itself, which owns approvals, artifacts, events, ownership, and operational state.

---

## Future design questions

**Sessions as supervision roots:** The current implementation centralizes session state for simplicity. Future iterations may adopt actor-style supervision semantics similar to an OTP supervisor model, where sessions, agents, approvals, and transports become independently supervised runtime components. `crates/session`'s already-built (if not yet wired) actor/effect model is a plausible substrate for this, if it's ever given real callers.

**Transcription for voice artifacts:** Voice memos are currently stored as raw audio and rendered with a native player. Automatic transcription (Whisper or provider API) would make voice content searchable and indexable alongside other artifact text.

**Wiring the session crate up as the actual runtime source of truth.** This is the intended end state, not a hypothetical — see [The session crate](#the-session-crate-a-partially-wired-state-machine) for exactly what's real today (cold-start replay, a complete live effect interpreter, near-total event-kind coverage on the input side, and a reflector with a real producer via saga dispatch) versus what's left (flipping write-ownership for the newly-bridged event kinds from shadow- to real-persist, which needs a reply-channel mechanism on the mailbox before REST handlers can depend on it). Scoped as an incremental, per-event-kind migration. The codebase already demonstrates the pattern for ~19 event kinds rather than a rewrite.
