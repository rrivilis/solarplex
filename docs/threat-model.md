# Solarplex Threat Model

This document describes the trust boundaries, principal hierarchy, and known
threat surface of the Solarplex architecture as of the current implementation.
It is a living document, so each architectural change should revisit the relevant
sections.

## Table of contents

- [1. Principals and trust levels](#1-principals-and-trust-levels)
- [2. Trust boundaries](#2-trust-boundaries)
- [3. Authentication paths](#3-authentication-paths)
  - [3.1 Human path (OIDC)](#31-human-path-oidc)
  - [3.2 Agent path (join_token)](#32-agent-path-join_token)
  - [3.3 Tokenless membership path (closed)](#33-tokenless-membership-path-closed)
- [4. Authorization model](#4-authorization-model)
  - [4.1 Epoch authority semantics](#41-epoch-authority-semantics)
  - [4.2 MCP object adapter model (sidecar authorization architecture)](#42-mcp-object-adapter-model-sidecar-authorization-architecture)
  - [4.3 Authority graph rewrite rules](#43-authority-graph-rewrite-rules)
  - [4.4 Protection ring model](#44-protection-ring-model)
    - [Ring 0: Declarative mutations, atomic CAS](#ring-0-declarative-mutations-atomic-cas)
    - [Ring 1: Filesystem writes, authorize-and-attest](#ring-1-filesystem-writes-authorize-and-attest)
    - [Ring 2: Shell commands and imperative effects](#ring-2-shell-commands-and-imperative-effects)
  - [4.5 DB security hardening (migration 015)](#45-db-security-hardening-migration-015)
  - [4.6 Three-process authority isolation (adapter / shim / guardian)](#46-three-process-authority-isolation-adapter--shim--guardian)
    - [Process roles](#process-roles)
    - [IPC flows](#ipc-flows)
    - [Key security invariant: no single-process compromise is sufficient](#key-security-invariant-no-single-process-compromise-is-sufficient)
    - [IMA appraisal + dm-verity (tooling built; inert until enabled per host)](#ima-appraisal--dm-verity-tooling-built-inert-until-enabled-per-host)
    - [Explicitly out of scope (for now): UEFI Secure Boot / measured boot](#explicitly-out-of-scope-for-now-uefi-secure-boot--measured-boot)
- [5. Shell command capture (opt-in)](#5-shell-command-capture-opt-in)
- [6. Plumbing and URI dispatch](#6-plumbing-and-uri-dispatch)
- [7. Artifact content scanning](#7-artifact-content-scanning)
  - [7.1 Sync scan path (sidecar, before LLM sees content)](#71-sync-scan-path-sidecar-before-llm-sees-content)
  - [7.2 Async scan path (sidecar → server, background)](#72-async-scan-path-sidecar--server-background)
  - [7.3 Server-side reputation (migration 017)](#73-server-side-reputation-migration-017)
- [8. WebSocket channel](#8-websocket-channel)
- [9. Tuple-space auth query layer](#9-tuple-space-auth-query-layer)
- [10. Data sensitivity and retention](#10-data-sensitivity-and-retention)
- [11. Known gaps and future work](#11-known-gaps-and-future-work)
  - [11.1 Three-process model gaps (introduced in v1 shim/guardian split)](#111-three-process-model-gaps-introduced-in-v1-shimguardian-split)
  - [11.2 Pre-existing gaps (unchanged)](#112-pre-existing-gaps-unchanged)
- [12. Cryptographic dependencies](#12-cryptographic-dependencies)
- [13. Secrets management (static credentials)](#13-secrets-management-static-credentials)
  - [13.1 Design summary](#131-design-summary)
  - [13.2 Storage and access (layers 2, 3)](#132-storage-and-access-layers-2-3)
  - [13.3 Rotation (layer 5)](#133-rotation-layer-5)
  - [13.4 Delivery (layer 4)](#134-delivery-layer-4)
  - [13.5 What this design does and does not protect against](#135-what-this-design-does-and-does-not-protect-against)
  - [13.6 Verification performed](#136-verification-performed)

---

## 1. Principals and trust levels

| Principal | How they authenticate | Trust level |
|---|---|---|
| **Human actor** | OIDC → opaque `sp_token` in `human_sessions` | Verified identity; authorization via session role + cap DAG |
| **Agent (sidecar)** | Single-use `join_token` issued by UI; exchanged at WS attach | Scoped to session; permissions constrained by cap permissions array |
| **Delegated sub-cap** | Child token derived from agent's root cap; `parent_cap` set | Attenuated; can only narrow the parent's permission set |
| **Server process** | Not a principal; owns the DB and event log | Trusted infrastructure |
| **Unauthenticated caller** | None | No access beyond public OIDC redirect endpoints |

Trust flows downward only. A child cap cannot exceed the permissions of its
parent. An agent cannot grant a sub-cap tools it does not itself hold.

---

## 2. Trust boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Browser / human client                                  │
│  OIDC flow → sp_token (7-day, multi-use)                │
└─────────────────────┬───────────────────────────────────┘
                      │  HTTPS + sp_token on WS connect
                      │
┌─────────────────────▼───────────────────────────────────┐
│  Solarplex server                                        │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │  OIDC filter│  │  WS handler  │  │  REST routes   │ │
│  │  (identity) │  │  (session)   │  │  (read/write)  │ │
│  └──────┬──────┘  └──────┬───────┘  └───────┬────────┘ │
│         │                │                   │           │
│  ┌──────▼────────────────▼───────────────────▼────────┐ │
│  │  Cap DAG (authorization)                           │ │
│  │  session_tokens + approval_requests +               │ │
│  │  execution_receipts / mcp_methods (ORB, §4.2)       │ │
│  └────────────────────────────────────────────────────┘ │
│                       │                                  │
│  ┌────────────────────▼───────────────────────────────┐ │
│  │  Postgres (append-only event log + fact tables)    │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                      ▲
                      │  join_token (single-use) + actor_id
┌─────────────────────┴───────────────────────────────────┐
│  Agent process stack                                     │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ solarplex-shim (trusted: session-binding + gating) │ │
│  │  • holds session token and cap material            │ │
│  │  • runs ring-2 scout, calls approval API           │ │
│  │  • issues ProposalDecision to adapter              │ │
│  └──────────────┬──────────────────────┬──────────────┘ │
│    socketpair,   │                     │   socketpair,   │
│  fd 3, no listen │                     │ fd 4, no listen │
│  ┌──────────────▼──────────┐  ┌────────▼─────────────┐ │
│  │ solarplex-adapter       │  │ solarplex-guardian    │ │
│  │ (untrusted: relay only) │  │ (trusted: exec only)  │ │
│  │  • MCP proxy            │  │  • bwrap+landlock+    │ │
│  │  • proposes tool calls  │  │    seccomp sandbox    │ │
│  │  • no approval authority│  │  • verifies approval  │ │
│  └─────────────────────────┘  │    with server before │ │
│                                │    every execution    │ │
│                                └──────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Key separation**: OIDC answers "who are you?" (identity). The cap DAG answers
"what can you do?" (authorization). These layers must never be merged. A valid
OIDC `sp_token` proves identity; it does not grant any session permission beyond
membership.

---

## 3. Authentication paths

### 3.1 Human path (OIDC)

1. Browser calls `GET /auth/oidc/start`.
2. Server generates PKCE pair + CSRF state, stores `(verifier, nonce)` in an
   in-memory DashMap keyed by state, redirects to provider.
3. Provider authenticates user, redirects to `GET /auth/oidc/callback?code=…&state=…`.
4. Server validates state (CSRF guard; single-use via `DashMap::remove`),
   exchanges code + PKCE verifier for ID token, verifies signature + nonce.
5. `(sub, provider)` → `actor_id` mapping: re-uses existing actor on repeat
   login, creates new actor on first login.
6. Issues opaque Solarplex `sp_token` (ULID, 7-day TTL) in `human_sessions`.
7. Redirects to frontend with token in URL fragment (`#sp_token=…`) to keep it
   off server access logs and browser history.

### 3.2 Agent path (join_token)

1. Human issues an attach token via `POST /api/sessions/:id/caps`.
2. Token is single-use (validated and consumed atomically via `UPDATE … SET used_at = NOW()`).
3. Agent sidecar connects to WS with `?actor_id=…&token=<join_token>`.
4. On success, agent is added as a session member; token cannot be replayed.

### 3.3 Tokenless membership path (closed)

The legacy path that allowed `?actor_id=…` with no token (relying on existing
session membership, caller-supplied identity) is **hard-gated**.

```
if query.token.is_none() {
    return 401 "join_token required for agent connections"
}
```

Every WS connection must present either `sp_token` (human OIDC path) or both
`actor_id` + `join_token` (agent path). There is no unauthenticated membership
check path remaining.

---

## 4. Authorization model

Authorization is enforced at two layers:

**Layer 1 — Session membership role**
- `owner`: full control including ownership transfer, member management
- `collaborator`: create/delete own artifacts, vote on approvals, issue caps
- `observer`: read-only; cannot vote or create artifacts
- `agent`: automated participant; permissions further constrained by cap

**Layer 2 — Capability DAG**
- `session_tokens` table stores caps with `parent_cap` forming a delegation tree
- Each cap carries a `permissions` array (empty = all tools permitted)
- Child caps can only narrow, never expand: a delegated cap with
  `["read_artifact"]` cannot grant sub-caps that include `"write_artifact"`
- `observed_seq` is the causal anchor: the issuer's view of session state at
  delegation time; used for epoch-based revocation

**Approval gate**
- Agents cannot execute sensitive tool calls without a matching `approval_request`
  record in `Approved` state
- Approval policy is per-session: `single_vote`, `majority`, or `unanimous`
- Eligible voters are session members with `can_approve = true` (owner or collaborator)

### 4.1 Epoch authority semantics

This section records a non-obvious architectural property introduced by the
epoch revocation system (migration 011) that has material implications for
how you reason about threats and trust.

**Caps are pointers, not bearer tokens.**

In the canonical capability-system model, the token is the authority as a
bearer credential that is self-contained.  Revocation is famously hard in
pure cap systems because authority has already been handed off and there is
no global namespace to update.

Solarplex caps do NOT work this way.  A cap token is a
`(session_id, epoch, stratum, permissions)` tuple that dereferences into
the authority namespace defined by the session's epoch register
(`session_epochs`).  The register is the authority; the cap is a well-typed
pointer with an attenuation mask layered on top.

This is closer to the **segment-descriptor model** from the original
Lampson/Dennis hardware capability literature than to POSIX file descriptors
or Macaroons.  A cap asserts: "in the epoch in which I was issued, I have
permission to do X."  When the epoch flips, the pointer is dangling and the
authority segment it referenced no longer exists.

**Corollaries for threat reasoning:**

1. **Stolen caps don't survive epoch boundaries.**  An attacker who exfiltrates
   a cap token cannot replay it after a revocation that closes its epoch.
   The exchange endpoint rejects caps with `revoked_at IS NOT NULL`, and the
   fencing check closes live connections after the drain window.  This is
   strictly stronger than expiry-only revocation.

2. **Stratum is a stack depth, not just a label.**  The cap DAG is a
   shadow stack of attenuations on top of a single shared authority object.
   `stratum = 0` is the root frame; each delegation hop pushes a frame.
   A stratum-based revocation is a controlled stack unwind: everything at
   depth ≥ N is torn down in one UPDATE, preserving the shallower authority.

3. **The dirty snapshot is a page-fault marker, not a data-corruption marker.**
   When an epoch revocation fires, the snapshot is marked `dirty`.  The data
   in the snapshot (members, artifacts, approvals, context) is still correct.
   What changed is the *authority interpretation* of any cap-shaped reference
   in or adjacent to that snapshot — it was produced in an epoch that no
   longer exists.  The lazy recompute on cold-attach is the page-fault handler.

4. **The drain window is a TLB shootdown protocol.**  Operations that began
   before the epoch flip have causal consistency claims (`observed_seq ≤
   drain_seq`).  You cannot atomically reclaim authority from all in-flight
   work, so the system broadcasts the invalidation (`EpochAdvanced`), grants
   a wall-clock grace window, then closes remaining fenced connections.
   This is structurally identical to inter-processor TLB shootdown on a
   CR3 write: broadcast, wait for acknowledgement, reclaim.

5. **Authority is O(1) to check, O(n) to revoke at scale.**  Each individual
   cap check is `revoked_at IS NULL` — O(1) against the token row.  But
   stratum and epoch revocations touch O(n) cap rows in a single UPDATE.
   The enforcement cost is at revocation time, not at delegation time — the
   inverse of the traditional ACL/cap tradeoff.

### 4.2 MCP object adapter model (sidecar authorization architecture)

The sidecar does not *check* permissions. It does not hold any authorization authority and cannot self-
authorize anything. 

The sidecar's role is to adapt one interface (MCP JSON-RPC over stdio/HTTP,
as the AI client sees it) into another interface (Solarplex's method-
addressable execution namespace, as the server owns it). An adapter wraps an adaptee (the MCP subprocess) 
so that a client (the AI) can interact with the target interface (the authority-bearing broker) without
knowing the difference.

The adapter owns neither the authorization logic nor the canonical source of
truth for what args a tool call will execute with.  Both live on the server.

**The execution flow under this model:**

```
AI client (Claude Code)
   │
   │  tools/call { method, args }  [MCP JSON-RPC]
   ▼
Sidecar (object adapter)
   │
   │  POST /api/sessions/:id/invoke { cap_id, method, args }
   ▼
Server 
   │  1. Validate cap (epoch, revoked_at, expiry)
   │  2. Resolve method in mcp_methods registry
   │  3. Check cap.permissions ⊇ { method }
   │  4. If requires_approval=false → auto-approve
   │     If requires_approval=true  → emit ApprovalRequested event,
   │                                   block until human votes
   │  5. Issue execution_receipt { cap_id, method, args }
   │     — args stored server-side, authoritative
   ▼
Sidecar
   │  POST /api/sessions/:id/consume-receipt { receipt_id }
   │  ← receives server's canonical { args }
   │
   │  executes MCP subprocess with server-canonical args
   ▼
MCP subprocess (filesystem server, tool host, etc.)
```

**Why this closes the post-approval args-swap gap:**

In the previous sidecar architecture the approval gate asked the server "may
I run tool T with args A?" and the server replied "yes."  The sidecar then
ran the tool.  A compromised sidecar could present safe args for human
approval and execute dangerous args after receiving the green light —
a classic TOCTOU.

Under the ORB model there is no separate check-then-act.  The server issues
a receipt that *binds* the approved `(cap_id, method, args)` as an atomic
record.  The sidecar fetches the receipt and receives the server's args, not
its own.  The sidecar MUST execute those args verbatim — if it executes
different args, the observable output diverges from what the human approved,
which is detectable by the AI in its next turn and visible in the event log.

Formally: the receipt is the authorization AND the instruction.  The server
controls both what may run and what arguments it runs with.  The sidecar is
only the execution transport.

**What the sidecar is still trusted to do:**

The adapter model does not eliminate trust in the sidecar — it scopes it
precisely.  The sidecar is trusted to:

- Hold the stdio connection to the MCP subprocess faithfully (not swap the
  subprocess for a different one)
- Forward the receipt's args to the subprocess without modification
- Report the subprocess's response to the AI client without tampering
- Not execute tool calls that did not arrive via the ORB invoke path

A fully compromised sidecar binary could violate these properties.  The
threat model here is a *misconfigured or policy-violating* sidecar, not an
attacker who has already replaced the binary.  The receipt model eliminates
a specific, previously-open trust gap at the human approval gate; it does not
replace defense-in-depth for the sidecar process itself.

**Relationship to the cap DAG:**

Method addresses in the ORB (`"mcp.{slug}.{method}"`) compose directly with
the cap DAG's attenuation invariant.  A child cap cannot hold an address its
parent does not hold.  A delegated sub-agent cannot invoke a tool outside the
method set its root cap was scoped to, regardless of what the sidecar
requests.  The ORB is not a separate authorization system — it is the same
cap DAG, extended with typed addresses instead of free tool-name strings.

### 4.3 Authority graph rewrite rules

The entire trust boundary story compresses to a graph with three rewrite rules.

**State:**

```
G = (V, E)

V = cap nodes   { (session_id, epoch, stratum, permissions, actor_id) }
E = parent edges { parent_cap FK }

Invariant: exactly one active root (stratum=0, revoked_at IS NULL) per live epoch.
```

**The three operations:**

| Operation | Effect on G | Epoch | Rust analogue |
|---|---|---|---|
| `delegate(parent, actor, perms⊆parent.perms)` | Add child node; extend E | preserved | restricted borrow |
| `revoke(scope)` | Mark scope invalid; advance epoch | +1 | `drop()` |
| `transfer(old_root, new_actor)` | Replace root; reroot E; retire old | preserved | `move` |

Every authority state transition in Solarplex is a composition of these three rewrites.

**delegate()** — extends the delegation tree downward.

```
pre:  perms(child) ⊆ perms(parent)   [attenuation invariant]
post: new node at stratum = parent.stratum + 1, same epoch as parent
      E ← E ∪ { child → parent }
```

Enforced: `Authority::delegate()` rejects any `perms` not held by the parent before touching the DB.

**revoke()** — closes an epoch, invalidating a generation of authority.

```
pre:  scope ∈ { subtree(cap), stratum≥N, epoch }
post: all nodes in scope: revoked_at = NOW()
      epoch register: epoch ← epoch + 1      [for stratum/epoch scope]
      lineage frozen as history              [tree topology preserved, nodes invalidated]
```

Audit marker: `revoked_at IS NOT NULL`, `transferred_to IS NULL`.

The drain window is the grace period between the epoch flip and connection teardown (§4.1 corollary 4).

**transfer()** — cooperative root replacement; preserves the epoch.

```
pre:  old_root = active root cap for from-actor
post: new_root inserted (stratum=0, same epoch, inherits old_root.permissions)
      E: ∀ e ∈ children(old_root): parent(e) ← new_root   [reparented atomically]
      old_root: revoked_at = NOW(), transferred_to = new_root.id
```

Audit marker: `revoked_at IS NOT NULL`, `transferred_to IS NOT NULL`.

**Why the audit markers matter:** a revocation in the log is a security event — compromised agent, explicit operator teardown, trust violation. A transfer in the log is a lifecycle event — scheduled handoff, human delegation. The distinction is recoverable from the DB without out-of-band records.

**Invariant maintenance:**

The "exactly one active root per live epoch" invariant is maintained by the transfer transaction atomicity: INSERT new root → reroot children → retire old root in one `BEGIN/COMMIT`. The partial-order of writes ensures the FK constraint (`transferred_to → session_tokens.id`) is satisfied before commit.

**Session ownership as a special case:**

`sessions::transfer_ownership_in_tx` performs a transfer() on the cap DAG and updates `session_memberships.role` in the same transaction. The role field is currently a display label (§4.3 migration note below) — the cap DAG root is the authoritative ownership record.

**Implementation mapping:**

| Algebra | DB primitive | Rust API |
|---|---|---|
| delegate | `tokens::insert` (parent_cap set) | `Authority::delegate()` |
| revoke(subtree) | `tokens::revoke_cap_subtree` | `AuthorityArena::revoke_subtree()` |
| revoke(stratum≥N) | `tokens::revoke_by_stratum` + epoch advance | `AuthorityArena::revoke_by_stratum()` |
| revoke(epoch) | `tokens::revoke_epoch` + epoch advance | `AuthorityArena::revoke_epoch()` |
| transfer | `tokens::find_root_cap_in_tx` + `tokens::transfer_root_in_tx` | `AuthorityArena::transfer_root()` |

**Migration plan for `session_memberships.role`:**

Currently role is an actor flag on `session_memberships` serving two purposes:
authorization (what can this actor do?) and display (how is this actor labeled?).
The cap DAG is now the authoritative authorization source; `role` is a display label.

Planned migration path:
1. *(now)* role = display label; cap DAG authoritative for auth.  
   `sessions::transfer_ownership_in_tx` keeps both in sync within one transaction.
2. Add `cap_id FK` on `session_memberships` pointing to the member's root cap.
3. Derive role from cap permissions (owner_perms → "owner", etc.) at query time.
4. Drop `session_memberships.role`; role becomes a computed projection of the cap DAG.

Step 2 is blocked on defining the canonical owner/collaborator/observer permission sets.

---

### 4.4 Protection ring model

Every mutation an agent can produce falls into one of three rings.  The ring
determines the available commit primitive and therefore the honest strength of
the security guarantee.  The type system in `protocol::effects` encodes this
directly — Ring 0/1/2 are not policy labels, they are the actual locations of
the guarantee-strength claims.

```
Ring 0 — Solarplex-managed state    Postgres CAS       prevention
Ring 1 — Filesystem writes          POSIX write        detection-in-log
Ring 2 — Shell / imperative         human approval     prevention (sandbox) + detection
```

The commit barrier checks two orthogonal invariants at the same point:

- **Authority** (cap DAG): "may this principal cause this effect?"
- **Consistency** (CAS hash): "may this effect land against the state it claims to have read?"

Ring 0 enforces both.  Ring 1 enforces authority; consistency is detected
post-hoc.  Ring 2 enforces authority; consistency is delegated to the human
and augmented by speculative pre-execution (§ below) and sandbox enforcement
derived from the approved `DeclaredEffects`.

#### Ring 0: Declarative mutations, atomic CAS

Applies to: artifact content updates, context entries, and any future
Solarplex-managed entity.

**Flow:**

```
sidecar                          server (Postgres)
   │                                    │
   ├─ /invoke (cap + method + args) ───►│
   │◄── receipt (args bound) ───────────┤
   │                                    │
   ├─ /propose (receipt_id,             │
   │            effect_type,            │
   │            effect_payload,         │
   │            expected_hash_before,   │
   │            claimed_hash_after) ───►│
   │◄── proposal_id ────────────────────┤
   │                                    │
   ├─ /proposals/:id/commit ──────────►│  ← BEGIN
   │                                   │    SELECT artifact FOR UPDATE
   │                                   │    sha256(storage_ref) == H_before?  → reject if not
   │                                   │    sha256(new_content) == H_after?   → reject if not
   │                                   │    UPDATE artifact, mark committed
   │◄── committed ─────────────────────┤  ← COMMIT
```

The decisive word is **expected_hash_before**.  The commit path executes
`BEGIN; SELECT artifact FOR UPDATE; hash; compare; apply; verify H_after;
mark committed; COMMIT` as a single Postgres transaction.  Serializable
isolation ensures no concurrent write can interleave.

**What this prevents:**

- Proposals cannot land against stale state — a concurrent mutation invalidates
  H_before and the server rejects.
- Post-approval content swap is closed — the receipt binds `canonical_args_hash`
  which the propose endpoint validates against the receipt's actual args.
- Double-commit is impossible — the `UNIQUE (receipt_id)` constraint on
  `write_proposals` prevents submitting two proposals for the same receipt.

**Effect types and hash semantics:**

| Effect type | H_before target | H_after target | Notes |
|---|---|---|---|
| `artifact_patch` | sha256(current storage_ref) | sha256(new content) | Full content replace; strong CAS |
| `context_entry` | ordering anchor (seq) | not checked | Append-only; concurrent appends both succeed |

#### Ring 1: Filesystem writes, authorize-and-attest

Applies to: any tool that writes to the user's local filesystem.

**Why CAS is unavailable here:**

The POSIX filesystem provides no atomic compare-and-swap primitive,
regardless of which process executes the write.  The sequence
`read → compare → write` is inherently non-atomic at the OS level;
another process can modify the file between `read` and `write`.
This is not a server trust issue — nobody can provide the strong form on
a filesystem.  The Ring-0 commit works only because Postgres provides
serializable isolation; no filesystem provides an equivalent envelope.

**Flow:**

```
agent                             sidecar                    server
  │                                  │                          │
  │── tool call (write_file) ───────►│                          │
  │                                  ├─ /invoke ───────────────►│
  │                                  │◄── receipt (with args    │
  │                                  │    bound: path, H_before,│
  │                                  │    H_after, content) ────┤
  │                                  │                          │
  │                                  ├─ read file ──────────────┤ (local)
  │                                  │  sha256(before) → observed_H_before
  │                                  │                          │
  │                                  ├─ write file ─────────────┤ (local)
  │                                  │                          │
  │                                  ├─ read file again ────────┤ (local)
  │                                  │  sha256(after) → actual_H_after
  │                                  │                          │
  │                                  ├─ /attest ───────────────►│
  │                                  │  (receipt_id, path,      │
  │                                  │   approved_H_before,     │
  │                                  │   approved_H_after,      │
  │                                  │   observed_H_before,     │
  │                                  │   actual_H_after) ───────┤
  │                                  │◄── attestation_id,       │
  │                                  │    hash_mismatch ────────┤
```

The human approval shows `(path, expected_before_hash, proposed_diff,
expected_after_hash)` — not just `(path, args)`.  The receipt binds all
four values.  The sidecar attests the observed values immediately after
execution.

**What `hash_mismatch = true` means:**

- `observed_H_before ≠ approved_H_before`: the file was modified between
  approval and write — a concurrent write, a race, or a compromised sidecar
  that swapped the write target.
- `actual_H_after ≠ approved_H_after`: the write produced a different result
  than declared — the tool used content different from the receipt's bound args.

Either case is recorded as a **queryable security event** in
`file_write_attestations` with `hash_mismatch = true`.  The
`GET /api/sessions/:id/attestations?mismatch_only=true` endpoint surfaces
these for auditing and alerting.

**What this does NOT prevent:**

A compromised sidecar binary can lie in the attestation.  The authorize-and-attest
model is **detection, not prevention** at the filesystem layer.  The invariant
enforced is: if the write was honest and the sidecar was not compromised, then
any divergence from the approved hashes is a recorded, queryable event.

#### Ring 2: Shell commands and imperative effects

Applies to: shell-execution tools, network calls, long-running processes, and
anything whose effect is not a declared diff over named state.

These are **opaque at the primitive level** — a command plan `(run ./deploy.sh)`
cannot be hash-fenced because the effect is not a declared content transition.
They pass through the human approval gate.

**Runahead scout — learning mode path**

The scout→`DeclaredEffects` pipeline is Solarplex's learning mode: the scout
speculatively executes the command, observes its actual syscall behaviour, and
promotes that observation into the sandbox policy before the human votes.  This
is the same model as TOMOYO Linux's learning mode — observe first, enforce
from the observation — applied at the sidecar layer rather than the kernel LSM
layer.

During the human approval window (idle latency ≈ cache-miss latency) the sidecar
executes the command under `strace(1)` on Linux, tracing `openat`, `unlinkat`,
`unlink`, `renameat`, `rename`, `connect`, and `execve`.  It captures a
`ScoutManifest`:

| Field | Content |
|---|---|
| `file_reads` | Paths opened with O_RDONLY |
| `file_effects` | Per-path `FileEvent { path, ops: FileOps }` — see table below |
| `network_connects` | IPv4 destinations ("ip:port") from connect(2) |
| `subprocesses` | Executables launched via execve(2) |
| `sandbox_backend` | `"strace"` on Linux with strace(1); `"none"` otherwise |
| `truncated` | True if the event cap (~1000 events) was hit |

`FileOps` captures per-operation granularity for each path, mapped from
strace output:

| Op | Strace source | Landlock `AccessFs` flags |
|---|---|---|
| `create` | `openat` with `O_CREAT` | `MAKE_REG \| MAKE_DIR \| MAKE_FIFO \| MAKE_SOCK \| MAKE_CHAR \| MAKE_BLOCK \| MAKE_SYM` |
| `write` | `openat` with `O_WRONLY \| O_RDWR \| O_TRUNC` | `WRITE_FILE \| TRUNCATE` |
| `delete` | `unlinkat`, `unlink` | `REMOVE_FILE \| REMOVE_DIR` |
| `rename` | `renameat`, `rename` | `REMOVE_FILE \| REMOVE_DIR \| MAKE_REG \| MAKE_DIR \| MAKE_SYM` |

Rename events emit two `FileEvent` entries: the source path gets
`delete + rename` ops; the destination gets `create + rename` ops.  When the
same path appears multiple times across the exec tree, ops are **unioned** — the
declared policy is the union of all observed operations (v1 policy; per-exec-domain
granularity is a planned extension).

The manifest is PATCHed to the approval record immediately upon scout
completion — **before the human votes** — so the approval UI can display
concrete predicted effects alongside the approval request.

After real execution, the sidecar captures an `ExecutionManifest` (mtime/size
snapshot of the scout's predicted effect paths, before and after) and compares:

- **Missing writes**: paths the scout predicted would change that didn't.
- **Unexpected writes**: paths that changed but weren't in the scout's effect list.

`manifest_diverged = true` is a **Ring-2 security event** stored permanently in
`approval_requests`.  It triggers a WARN log and is queryable via the index on
`(session_id) WHERE manifest_diverged = true`.  It does not block or roll back
execution — the human approval decision is authoritative.

**Ring-2 sandbox executor — prevention from declared effects**

After the human approves, the guardian (not the sidecar — see §4.6's
three-process split) executes the command inside a layered sandbox derived
exclusively from the `DeclaredEffects` stored in the ORB receipt:

1. **bwrap namespace** (Linux): read-only rootfs bind; isolated `/tmp`; writable
   bind-mounts for each path in `file_effects`; `--unshare-net` when
   `network_access = false`; `--unshare-pid`, `--unshare-ipc` always.

2. **Landlock FS rules** (Linux ≥ 5.13): applied by the `sandbox-entry` guardian
   subcommand after bwrap's namespace setup completes.  Each path in `file_effects`
   receives exactly the `AccessFs` flags corresponding to its declared `FileOps`
   (see table above) — not a blanket write grant.  Inheritable across all `execve`
   calls inside the sandbox. This is the actual, currently-effective enforcement
   boundary for declared file effects — see point 3's second layer below.

3. **Seccomp, two layers**:

   - **Classic BPF denylist** (unchanged): `PR_SET_NO_NEW_PRIVS` +
     `SECCOMP_MODE_FILTER`; always denies `ptrace`, `kexec_load`,
     `process_vm_readv/writev`, `perf_event_open`, `io_uring_setup/enter/register`
     (closes seccomp's documented io_uring blind spot — the kernel only sees
     `io_uring_enter()`, not the individual SQEs its workers execute);
     conditionally denies socket/connect/bind/listen/accept when
     `network_access = false` and `execve/execveat` when `subprocess_exec = false`.

   - **Live seccomp-notify broker** (new architecture; empirically validated
     end-to-end on a real kernel, including the `ADDFD` grant path itself —
     see below): layered on top of the classic filter with
     `SECCOMP_FILTER_FLAG_NEW_LISTENER`, covering only pathname-resolving
     syscalls (`openat`, `openat2`, `unlink`, `unlinkat`, `rename`, `renameat`,
     `renameat2`). The guardian is no longer just a spawn-and-wait supervisor —
     for each sandboxed exec it runs a persistent, single-reactor process
     supervisor (raw `io_uring`, not tokio: the trust boundary here is between
     the guardian's own supervisory ring and the untrusted sandboxed child, so
     the two are kept structurally distinct rather than blurred through a
     shared async runtime) that concurrently watches the child's `pidfd`,
     the seccomp notify fd, and its stdout/stderr pipes via multishot polls,
     for the exec's whole lifetime. On each trapped syscall it resolves the
     requested path itself (TOCTOU-safe: read once from the tracee's memory,
     matched against `DeclaredEffects`, never re-resolved) and either:

     - **Grants** (`SECCOMP_IOCTL_NOTIF_ADDFD` + `SECCOMP_ADDFD_FLAG_SEND`) —
       the guardian opens the object in its own resolved context and injects
       the fd directly; the tracee's own `openat2` never runs at all, closing
       the TOCTOU window between "declared effect" and "kernel enforces it"
       that the classic-filter-only design left open, or
     - **Continues** (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) — lets the real
       syscall proceed, backstopped by Landlock (point 2) exactly as before.

     **Verified end-to-end on a real kernel** (see §11.1's now-Implemented
     entry for the full story): `ADDFD`+`SEND` correctly wakes the tracee
     and the granted write actually lands. Two real bugs stood between
     "designed" and "works" here, both found via live kernel-level testing,
     not by inspection — `SECCOMP_ADDFD_FLAG_SEND`'s bit value was wrong
     (silently colliding with a *different* flag, `SETFD`), and the
     resolved path was always opened read-only regardless of what the
     tracee actually requested. All five test scenarios pass: the declared
     write lands, an undeclared write is denied by Landlock, an undeclared
     read still succeeds (blanket read access), `io_uring_setup` still
     hard-fails via the classic denylist, and a delete against a
     write-only-declared path correctly falls through to Landlock denial.

The sandbox is a projection of the ORB receipt: a command cannot access more
filesystem or network than its approved `DeclaredEffects` declare.  The scout
manifest (produced during the approval window) populates `DeclaredEffects` before
the human votes, so the sandbox policy is visible at approval time.

On non-Linux platforms or when bwrap is absent, execution falls back to
unsandboxed with a WARN log.  Set `SOLARPLEX_REQUIRE_SANDBOX=1` to make this
a hard failure in production.

**Bounded issue pool — reorder buffer framing**

Scouts are managed by `ScoutPool`, a collection of per-category `SubPool`s.
Each sub-pool is a bounded FIFO queue drained by a fixed set of worker tasks.
The concurrency model maps directly onto the ROB abstraction that ops teams
can reason about:

| ROB concept | Implementation |
|---|---|
| ROB slot | `ScoutJob` enqueued in a `SubPool` |
| Issue width | `SubPool` worker count |
| Speculative execution unit | strace worker task |
| Speculative result record | `oneshot::Receiver<ScoutManifest>` |
| Commit | real execution + post-snapshot diff |
| Retire | close approval entry + PATCH `execution_manifest` |

Per-category sub-pools give true isolation — a stalled `prod_deploy` queue
cannot head-of-line block `low_risk` scouts.  Orgs tune their own scheduling
policy rather than adopting a canonical effect-type ontology:

```
default:      width=4,  queue=64    // general scouts
prod_deploy:  width=1,  queue=4     // serialized; never speculate two prod deploys
low_risk:     width=16, queue=256   // saturate for safe, fast operations
```

Queue-full drops the job with a WARN log.  Graceful degradation is the correct
policy: the scout is heuristic, and the approval flow continues without it.
Category routing is an extension point; the proxy currently routes all jobs to
the default pool.

**Platform support:**

| Platform | Observation backend | Effect coverage |
|---|---|---|
| Linux (strace installed) | `strace -f` tracing `openat`, `unlinkat`, `unlink`, `renameat`, `rename`, `connect`, `execve` | Full `FileOps`-granular manifest |
| Linux (strace absent) | `none` | Filesystem snapshot diff only |
| macOS / Windows | `none` | Filesystem snapshot diff only |

**Service scope summary:**

> Declarative mutations over Solarplex-managed state commit under server-side
> atomic CAS preconditions (Ring 0) and cannot land against stale state.
>
> Filesystem writes (Ring 1) are declarative but execute over a
> non-transactional namespace where atomic CAS is unavailable to any party;
> they are authorized via receipt arg-binding with before/after hashes and
> verified post-hoc via sidecar attestation — **detection, not prevention**.
>
> Shell commands (Ring 2) are non-declarative and human-gated.  The runahead
> scout speculatively executes each command during the approval window,
> producing `DeclaredEffects` that enrich the human's decision surface and
> drive a bwrap/landlock/seccomp sandbox at execution time (**prevention**).
> Post-execution manifest comparison provides **detection** of divergence;
> the human approval decision remains authoritative.

---

### 4.5 DB security hardening (migration 015)

Two Postgres triggers reinforce cap DAG invariants at the storage layer,
providing a second line of defence independent of the application-level checks
in `tokens.rs`.

**Trigger 1 — `enforce_token_field_immutability` (BEFORE UPDATE)**

`session_tokens.permissions`, `.epoch`, and `.stratum` are immutable after
INSERT.  Any UPDATE that attempts to change these fields raises an exception:

```
session_tokens.permissions is immutable after insert — revoke and re-issue instead
```

This prevents a compromised application layer from silently widening a cap's
permission set without going through the delegation/revocation algebra.
The only legitimate way to change permissions is to revoke the cap and issue a
new one — which creates an audit trail.

**Trigger 2 — `enforce_token_epoch_coherence` (BEFORE INSERT)**

When a new child cap is inserted with a `parent_cap`, the trigger verifies:

1. The child's `epoch` matches the parent's `epoch` (cross-epoch cap trees are
   incoherent — a child cannot outlive its parent's epoch boundary).
2. The child's `session_id` matches the parent's `session_id` (cross-session
   cap reparenting is always a security error).

These checks mirror the application-layer invariants in `Authority::delegate()`
but fire unconditionally at the DB layer, regardless of which code path inserted
the row.

**`reroot_caps()` session scope fix**

`tokens::reroot_caps()` (used by `revoke --reroot` to preserve surviving
children of a revoked cap) previously accepted `old_parent_id` and
`new_parent_id` without filtering by `session_id`.  A bug or compromised
caller could reparent caps across sessions.  The fix adds a mandatory
`session_id` parameter and a `WHERE session_id = $3` clause to the UPDATE:

```sql
UPDATE session_tokens
SET    parent_cap = $2
WHERE  parent_cap = $1
  AND  session_id = $3          -- ← scope fix
  AND  revoked_at IS NULL
```

The DB trigger provides a second line of defence: even if the WHERE clause were
somehow bypassed, the trigger would reject any INSERT of a cross-session child.

---

### 4.6 Three-process authority isolation (adapter / shim / guardian)

The agent-side execution path is split across three separate OS processes. No
single process holds both decision authority **and** execution capability; a
successful compromise of any one process is not sufficient to cause unauthorized
execution.

#### Process roles

| Process | Binary | Trust level | What it can do | What it cannot do |
|---|---|---|---|---|
| **Adapter** | `solarplex-adapter` | Untrusted relay | Proxy MCP JSON-RPC; observe tool call args; propose tool calls to shim | Self-approve any proposal; talk to guardian directly; hold session token |
| **Shim** | `solarplex-shim` | Trusted gatekeeper | Hold session token + cap material; run ring-2 scout; create approval requests; issue `ProposalDecision` | Execute any command (no shell access); talk to upstream MCP directly |
| **Guardian** | `solarplex-guardian` | Trusted executor | Spawn sandboxed subprocesses (bwrap + landlock + seccomp) and supervise each one via a persistent per-exec reactor (§4.4); carry out a `ProposalDecision` | Create or vote on approval requests; hold or read session token; communicate with adapter |

This is a **positional authority** model: the shim holds credentials but has no
execution path; the guardian has an execution path but independently verifies
every decision with the server before acting.

#### IPC flows

IPC channels use Unix **socketpairs** created by the shim before exec-ing each
child.  One end of each pair is `dup2`'d to a well-known fd in the child:

- **fd 3** — shim↔adapter authority socket (adapter side)
- **fd 4** — shim↔guardian authority socket (guardian side)

Possession of the inherited fd IS the authority proof.  There is no listening
socket to discover or race against, no socket path in an env var to redirect,
no per-boot secret to exfiltrate from `/proc/self/environ`, and no `SO_PEERCRED`
PID check needed.  The kernel enforces that only a direct descendant of the
spawning process inherits an open fd.  Both children set `O_CLOEXEC` on their
authority fd immediately after startup so that bwrap sandbox children and
upstream MCP subprocesses cannot inherit it.

```
AI client
   │
   │  MCP JSON-RPC (stdio or HTTP)
   ▼
solarplex-adapter  ← inherits fd 3 (shim↔adapter socketpair, adapter side)
   │
   │  AdapterMessage::Propose(ProposalRequest)          socketpair fd 3
   ▼                                                    (fd possession = authority)
solarplex-shim ──── announces approval window ────────► server (Postgres PDP)
   │                poll / scout during human window
   │
   │  ShimMessage::Decision(ProposalDecision)
   ▼
solarplex-adapter
   │
   │  GuardianRequest { approval_id }        ← NO command/declared from adapter
   ▼                                                    socketpair fd 4
solarplex-guardian ← inherits fd 4 (shim↔guardian socketpair, guardian side)
   │
   │  GET /api/approvals/:id  (X-Session-Id + X-Actor-Id)
   ▼
server — returns { decision, approved_command, declared_effects }
          (3-second timeout; fail-closed on error)
   │
   │  sandbox-entry subcommand (bwrap → landlock → seccomp → execvp)
   ▼
command from server-canonical record executed inside sandbox — guardian then
runs a persistent single-reactor supervisor (io_uring) for the exec's whole
lifetime, not a spawn-and-wait: watches pidfd/notify-fd/stdout/stderr
concurrently and brokers seccomp-notify grants (see §4.4's "Ring-2 sandbox
executor" for the mechanism and its current known issue)
   │
   │  GuardianResponse { exit_code, stdout, stderr }   socketpair fd 4
   ▼
solarplex-shim
   │
   │  AdapterMessage::ExecDone(ExecDoneNotice)         socketpair fd 3
   ▼
solarplex-shim ── ring-2 divergence check + ring-1 attestation ──► server
```

#### Key security invariant: no single-process compromise is sufficient

**Compromised adapter**: it can only propose tool calls that still pass through
the shim's approval gate. It cannot self-approve, skip the gate, or speak to
the guardian. It holds no session token.

**Compromised shim**: it can issue a forged `ProposalDecision { granted: true }`
to the adapter. The guardian will still independently verify with the server
before executing. A forged decision is caught at the guardian's verification
step — the server has no matching `Approved` record, so the guardian declines.

**Compromised guardian**: it can execute arbitrary commands inside its sandbox.
However, it cannot impersonate the shim to the adapter and cannot create an
approval record on the server. It is the only process that can actually run
commands, so this is the highest-impact single-process compromise.

For full bypass (execution without human approval), an attacker must simultaneously
compromise both the guardian (to bypass its server check) and the server (to
fabricate an `Approved` record), or compromise both the shim (to fabricate a
`ProposalDecision`) and the guardian (to suppress its independent check).

#### IMA appraisal + dm-verity (tooling built; inert until enabled per host)

The three-process isolation model does not by itself verify that the binaries
themselves are the expected ones. A host-level attacker who can replace
`solarplex-guardian` with a malicious binary inherits the guardian's full
execution authority, bypassing the positional authority model entirely.

The mitigation is a two-layer binary integrity stack:

1. **dm-verity** (block-device layer): the read-only squashfs image
   containing the three binaries is covered by a dm-verity hash tree.  A
   modified binary produces a hash mismatch that dm-verity treats as an I/O
   error before any process can load it.  Built by
   `deploy/scripts/build-verity-image.sh` and delivered/mounted by the
   `solarplex_binary_integrity` Ansible role.

2. **IMA appraisal** (kernel LSM layer): `security.ima` extended attributes store
   per-file HMAC signatures verified by the kernel at `execve` time.  The kernel
   refuses to exec a binary whose signature does not match the trusted keypair.
   Signing is done by `deploy/scripts/sign-ima-binaries.sh`, deliberately run
   only on a dedicated signing host or CI job that holds the private key —
   it never touches the hosts that run the signed binaries, which only ever
   receive the public certificate (see that script's header comment).

Both layers now have real tooling (`deploy/scripts/`, `deploy/ansible/roles/
solarplex_binary_integrity/`), but activation is still a deployment-time
kernel configuration choice, not something a code change can flip on: the
routine Ansible play builds the verity image, signs are pre-applied
upstream, the IMA policy file and keyring-load unit are delivered — but
`ima_appraise` is not set on any host's kernel command line by that routine
play. That is a separate, explicitly one-time, one-host-at-a-time step
(`--tags enable_ima_appraisal`, see that task file's header comment) that
reboots the host, and it only ever sets **log mode** — appraisal failures
are recorded to the audit log without blocking exec. Flipping a given host
from log mode to enforce mode is intentionally not automated anywhere in
this repo; it's a manual action taken only after reviewing that host's own
audit log post-reboot, because an unattended flip to enforce on a policy
that's subtly wrong for one host (wrong fsmagic, keyring didn't load, cert
mismatch) means that host stops booting or stops running anything, not a
log line.

**Until a given host has actually run `enable_ima_appraisal` (and, by
separate manual action, been flipped from log to enforce)**, its binary
integrity is still mitigated only by OS-level access controls (file
permissions, SELinux/AppArmor policy) and process isolation — which are
weaker than measurement-based guarantees. Development and CI environments
do not run this stack at all. Key-provisioning into the kernel's `.ima`
keyring (`solarplex-ima-keyring.service`) is best-effort and depends on the
target kernel's own Secure Boot/MOK configuration — hosts that restrict
keyring modification more strictly need that cert enrolled through their
platform's own mechanism instead; this has not been validated against a
real host.

**Runtime detection (implemented, not a substitute for the above).** The
guardian now does two things at startup, mirroring the fail-closed-unless-
opted-out shape already used for the Ring-2 sandbox (`find_bwrap()` /
`SOLARPLEX_ALLOW_UNSANDBOXED`, §4.4):

1. Unconditionally emits a `WARN`-level log naming this gap on every start —
   unchanged from before, still non-fatal by default, since neither layer is
   active in any deployment today (dev, CI, or production) and defaulting to
   fail-closed here would break all of them.
2. `SOLARPLEX_REQUIRE_IMA=1` is an explicit opt-in assertion for an operator
   who has actually deployed the kernel-level pieces: the guardian checks for
   `/sys/kernel/security/ima/policy` and refuses to start if it's absent,
   turning "IMA was supposed to be enabled but the policy didn't load" into a
   startup failure instead of a warning nobody reads.

This is a best-effort userspace signal, not a security control, and does not
change anything above: a binary already replaced by an attacker could patch
out or fool its own startup check just as easily as it could fabricate any
other self-report. The only trustworthy enforcement point remains the kernel
at `execve` time, before this code — or a substituted replacement of it —
ever runs. Path existence also does not by itself prove an appraisal rule
actually covers this specific binary; that still requires a human policy
audit. `SOLARPLEX_REQUIRE_IMA` exists purely to catch a *misconfigured*
deployment that believes this gap is closed when it isn't — it does not
close the gap itself, and the two-layer mitigation above, while built, has
not been enabled on any host yet.

#### Explicitly out of scope (for now): UEFI Secure Boot / measured boot

dm-verity and IMA appraisal above cover *a compromised running host*: an
attacker with root cannot silently substitute `solarplex-guardian` on disk.
Neither defends against *boot-chain tampering*: an attacker with physical or
console access to the machine before the OS is running, swapping the kernel,
initrd, or boot loader before dm-verity or IMA ever get a chance to run.
UEFI Secure Boot (optionally combined with a Unified Kernel Image and
TPM2-based measured boot / PCR sealing) is the standard answer to that
narrower threat, and was considered and deliberately deferred, not
overlooked:

- **The primary target hosting environment doesn't support it.** Hetzner
  Cloud's own FAQ states directly: "our cloud servers do not support vTPM
  (Virtual Trusted Platform Module) or TPM (Trusted Platform Module)" and
  "we do not support 'secure boot' on our cloud servers." A Unified Kernel
  Image gains its enforcement from UEFI verifying its signature before
  executing it; with no Secure Boot on the platform, nothing checks that
  signature, and the UKI degrades to a differently-packaged kernel + initrd
  + cmdline with no cryptographic backing, not the boundary it would be on
  hardware that supports the full chain.
- **The one TPM-dependent piece already in this design doesn't need
  measured boot to work.** `bootstrap_identity.yml`'s
  `systemd-creds encrypt --with-key=tpm2` call has no `--tpm2-pcrs=` flag,
  so it seals the per-host age identity to *that TPM chip existing*, not to
  a specific measured boot state; it doesn't actually need Secure Boot or
  PCR binding, just *some* TPM 2.0 device, real or virtual. On Hetzner
  Cloud specifically there is none at all (see above), so this step is
  untestable there regardless of the Secure Boot decision; validating it
  needs a host with a real or virtual TPM (a vTPM-enabled VM on another
  cloud provider, or Hetzner's dedicated/Robot line, which likely has a
  physical TPM on the motherboard, unconfirmed).
- **Enabling it on Hetzner's dedicated line has a real operational cost,
  not just a setup cost.** Hetzner's own dedicated-server docs allow
  enabling Secure Boot but explicitly do not support it: doing so with a
  custom (non-Hetzner) key chain breaks their Rescue System and
  `installimage` auto-installer, since neither is signed by a key the
  operator controls. That trades away Hetzner's remote recovery path for
  that host in exchange for a defense against a threat (a malicious or
  compromised hosting provider tampering with the boot chain, or an
  attacker with brief physical/console access) that is largely already
  accepted as part of trusting a hosting provider at all, the same way
  trusting AWS/GCP/Azure not to tamper with an instance's boot process is
  an accepted baseline on those platforms.

**Decision**: not pursued for now. Revisit if either (a) the actual
deployment target changes to a provider/host with native TPM + Secure Boot
support, or (b) the threat model is revised to explicitly include a
malicious-or-compromised hosting provider or a physical/console attacker as
in-scope, at which point the operational cost above becomes worth paying
deliberately, rather than defaulted into because the tooling exists.

---

## 5. Shell command capture (opt-in)

Shell command tracking is **off by default**. The fish adapter records only the
binary basename (`argv0`) in `ShellCommandStartedPayload`.

When `SOLARPLEX_TRACK_COMMANDS=1` is set:
- Full argv is captured and sent to the server
- A credential seatbelt (`first_credential_match`) runs client-side before
  transmission, checking 9 regex patterns (URL credentials, `--password` flags,
  `Authorization:` headers, env var assignments, common secret key formats)
- If a match fires: `tracked=true, redacted=true, command=None` — the payload
  records that a credential was detected but suppresses the argv
- The UI renders `[credential detected — argv suppressed]` for redacted events

**Documented seatbelt limitations** (not caught by design):
- Shell variable references (`curl -u $MY_TOKEN`) — the variable is not expanded
  before the check; users should not store secrets in shell vars
- Base64-encoded secrets (look like random strings)
- Heredoc content (stdin, not argv)
- Process substitution (`<(cat secret_file)`)

The primary defense is that tracking is off by default. The regex seatbelt is
defence-in-depth for opted-in sessions.

---

## 6. Plumbing and URI dispatch

The `sp plumb` subsystem routes text/URIs through user-defined rules, executing
shell commands. This creates an injection surface.

**Trust distinction: user-initiated vs. foreign-URI dispatch**

- `sp plumb run <text>` invoked by the user: trusted path; all rules can match
- `sp plumb run <uri>` invoked by WezTerm URI click (OSC-8): potentially foreign
  content if an agent or artifact injected a crafted hyperlink

**Mitigations in place**:
- `sanitize_terminal()` strips all ANSI/OSC escape sequences from foreign-authored
  content before it reaches `println!`, preventing terminal injection via the
  no-match output path
- All entity URIs use the `solarplex:` scheme; arbitrary `https://` URLs match
  the `xdg-open` rule only, which hands off to the OS browser — no arbitrary
  shell execution from a URL

**Untrusted-path gate (implemented)**: `plumb()` accepts an `is_untrusted: bool`
flag, threaded from the `--untrusted` CLI argument added to `PlumbCmd::Run`.
The OS URI handler `.desktop` file passes `--untrusted` unconditionally so all
WezTerm OSC-8 clicks land on the gated path.

Each built-in `Rule` carries `requires_trust: bool`:
- **`requires_trust = false`** (allowed on untrusted path): rules with
  ULID-constrained captures (`[0-9A-HJKMNP-TV-Za-z]+`) and read-only actions
  (`sp artifact get`, `sp context show`, `sp approval wait`, `sp session enter`,
  etc.), the `solarplex:` prefix stripper, bare ULID resolver, and `xdg-open`.
- **`requires_trust = true`** (blocked on untrusted path): `ask/(.*)` (`.`
  capture admits metacharacters), `act/…` (state-mutating transitions), and
  `actor/(\S+)` (`\S+` capture admits subshell characters).

All user-defined rules in `~/.config/solarplex/plumb.toml` are implicitly
`requires_trust = true`; the file is not loaded at all on the untrusted path.

---

## 7. Artifact content scanning

Artifacts are a primary injection vector: an agent or external source can embed
prompt-injection payloads, shell commands, or encoded exploits in artifact
content, which then reaches the LLM as trusted context.  The scanning pipeline
(migration 017) provides layered defenses on both the sync read path and an
async background path.

### 7.1 Sync scan path (sidecar, before LLM sees content)

**Aho-Corasick phrase filter (`sanitize_artifact_content`)**

A 14-pattern Aho-Corasick automaton (`aho-corasick = "1"`, case-insensitive,
`LeftmostFirst` match mode, compiled once into a `OnceLock`) strips known
prompt-injection phrases from artifact content before the LLM receives it.
Patterns include: `ignore previous instructions`, `ignore all previous`,
`disregard previous`, `forget your instructions`, `new instructions:`,
`system prompt:`, `###instruction`, `<|system|>`, `<|im_start|>`, and similar.
This runs in O(content_len) time regardless of pattern count.

**SHA-256 verdict lookup**

A SHA-256 digest of the raw content is computed immediately at `solarplex_read_artifact`
and `solarplex_create_artifact` time.  The sidecar calls
`GET /api/artifact-hashes/:sha256` with a 200 ms timeout and prepends a verdict
banner to the artifact presentation:

- `🚨 MALICIOUS — hash flagged by reputation DB`  for `malicious` verdicts
- `⚠ SUSPICIOUS — hash flagged by reputation DB`  for `suspicious` verdicts

This gives the LLM an explicit signal before it processes the content.

**`authored_by` provenance**

Every `ContextEntryAdded` WS event carries an `authored_by: Option<String>`
field identifying which actor (human, agent, or `None` for system) produced the
entry.  This allows audit queries to distinguish operator-authored context from
agent-generated context without reading event payload.

### 7.2 Async scan path (sidecar → server, background)

Immediately after read or create, `spawn_artifact_scan` launches a background
task (`tokio::spawn`) that does not block the LLM interaction:

**YARA-X scanner**

Four built-in rules compiled once into a `OnceLock<yara_x::Rules>` via
`yara-x = "0.12"` (pure-Rust):

| Rule | Detects |
|---|---|
| `prompt_injection` | 9 string patterns: `###instruction`, `<\|im_start\|>`, etc. |
| `encoded_payload` | Base64-encoded PowerShell or `echo … \| base64` pipelines |
| `shell_injection` | `curl … \| sh`, `nc -e /bin/sh`, `bash -i >& /dev/tcp` |
| `data_exfil` | `exfiltrate`, `curl -d … http://` |

Matching rule names are sent to `POST /api/artifact-hashes/scan-result`.

**TLSH locality-sensitive hash**

TLSH (`tlsh2 = { version = "1", features = ["diff"] }`) produces a 72-byte
fuzzy fingerprint for content ≥ 50 bytes.  Distance ≤ 50 (TLSH scale 0–300)
is treated as "same family."  The TLSH string is sent alongside YARA matches
to the server's scan-result endpoint.

### 7.3 Server-side reputation (migration 017)

**Prevalence gate**

Hashes seen fewer than `MIN_PREVALENCE = 5` times return `Verdict::Unknown`
regardless of family assignment.  This prevents single-occurrence noise (a
unique artifact nobody else has sent) from triggering false positives.

**Family graph: `sha256 → family_id`**

The server builds a family graph from two tables:

```
artifact_hashes  sha256 (PK), tlsh, family_id FK, seen_count, yara_matches, verdict_override
artifact_families  id (PK), name, verdict, tlsh_centroid, yara_rules[], member_count
```

Family assignment priority (in `POST /api/artifact-hashes/scan-result`):
1. **YARA match** - first matching rule creates or joins a YARA-named family;
   `infer_verdict_from_rule()` derives `malicious` (ransomware/trojan/malware)
   or `suspicious` (everything else)
2. **TLSH cluster** - nearest centroid by `TlshDefault::diff(…, false)`; joins
   if distance < 50, else creates a new `tlsh-cluster-{sha256[..8]}` family
3. **Manual override** - `verdict_override` field wins over family verdict at
   query time, enabling operator remediation without touching the family graph

**Count-Min Sketch (n-gram anomaly scoring)**

A 4×65536 Count-Min Sketch (`CmsState` in `AppState`) accumulates character
trigrams from all artifact content at creation time (server-side, shared across
all sessions).  After 500 samples (`CMS_BASELINE_SAMPLES`), `cms.score(content)`
returns the mean minimum frequency of a content's trigrams — low scores indicate
novel/anomalous n-gram distributions (potential zero-day injection patterns that
YARA rules don't cover).  The CMS lives in `Mutex<CmsState>` inside `AppState`;
its score is surfaced via `GET /api/artifact-hashes/:sha256` as `cms_score`.

**Known limitations**:
- Embeddings for semantic similarity clustering are deferred (no embedding
  model/API integrated yet); the family graph currently relies solely on YARA
  + TLSH
- Manual verdict override has no UI; must be set directly via DB
- CMS is in-memory only — restarting the server resets the baseline counter

---

## 8. WebSocket channel

- All WebSocket messages are JSON; no binary frames
- Session broadcast: every connected actor in a session receives all events
  (observer, collaborator, agent — no per-actor message filtering within a session)
- Directed messages (e.g., `approval.resolved` to a specific sidecar) use a
  per-actor `mpsc` channel; other actors do not receive them
- The server holds a live snapshot (`ArcSwap<Option<LiveSnapshot>>`) per session;
  on WS attach the snapshot is sent as the first message; subsequent events are
  projected onto it before broadcast

**Threat: session broadcast leaks to observers**
All connected actors see all events including approval content, artifact names,
and context entries. If an observer role is used to grant read-only access to
sensitive sessions, be aware that they see everything the session produces.
Per-event ACL is a future cap DAG extension.

---

## 9. Tuple-space auth query layer

`GET /api/auth/why`, `/api/auth/who-can`, `/api/auth/lineage` are **read-only
explanatory endpoints**, not enforcement points.

- They return a view of the current cap DAG state for debugging and auditing
- They do not modify any state and cannot be used to grant permissions
- Callers need no special authentication beyond a valid session context (the
  server's route-level auth applies)
- `entity_permissions_match()` is a heuristic: it matches tool name prefixes to
  entity types for readability. It is NOT the enforcement check — enforcement
  lives in the approval gate + cap DAG

---

## 10. Data sensitivity and retention

| Table | Sensitivity | Retention |
|---|---|---|
| `events` | Session data; may contain PII from context entries / artifacts | Append-only; no server-side deletion in v1; archived sessions are read-only |
| `actors` | Name + email (from OIDC) | Retained until explicit deletion |
| `human_sessions` | Opaque ULID tokens + OIDC sub | Revocable; expire after 7 days; `revoke_all` for account deletion |
| `session_tokens` | Agent cap tokens (already exchanged = single-use) | Retained for lineage audit trail; expired caps are not enforced but remain visible |
| `artifacts` | User-created content | Session-scoped; archived with session |

**Shell command argv** is stored in `events.payload` when the user has opted in
(`SOLARPLEX_TRACK_COMMANDS=1`) and the seatbelt did not fire. Do not enable
tracking on machines where shell commands regularly contain secrets.

---

## 11. Known gaps and future work

### 11.1 Three-process model gaps (introduced in v1 shim/guardian split)

| Gap | Severity | Notes |
|---|---|---|
| **IMA appraisal + dm-verity not enabled on any host** | **Medium** (was High) | Binary substitution of `solarplex-guardian` gives an attacker full execution authority. Tooling now exists — `deploy/scripts/build-verity-image.sh` + `sign-ima-binaries.sh` and the `solarplex_binary_integrity` Ansible role build the dm-verity image, deliver the IMA policy + signed binaries, and mount the verified image — but activation (`ima_appraise=log` on the kernel command line, then a later manual flip to enforce after per-host audit-log review) is still a one-time, one-host-at-a-time operator action, not run automatically by the routine deploy play. Downgraded from High because OS-level file permissions are no longer the *only* control once a host has actually run `--tags enable_ima_appraisal` — but severity stays elevated, not Closed, until that step has actually been run and validated against a real production host, which has not happened yet. See §4.6. The guardian emits a `WARN`-level log on every startup naming this gap, and `SOLARPLEX_REQUIRE_IMA=1` turns a missing/misconfigured policy into a startup failure instead — an opt-in misconfiguration check, not a substitute for the underlying kernel-level protection. |
| **UEFI Secure Boot / measured boot not pursued** | Deferred (explicit scope decision) | Covers boot-chain tampering (physical/console access before the OS runs), a narrower threat than what dm-verity + IMA appraisal above already cover (a compromised running host). Not pursued because the primary target, Hetzner Cloud, supports neither TPM/vTPM nor Secure Boot (confirmed directly against their FAQ): a Unified Kernel Image gains no enforcement without Secure Boot to verify its signature. The one TPM-dependent step already in this design (`bootstrap_identity.yml`'s age-identity sealing) doesn't need PCR binding/measured boot, just TPM presence, so it's separable from this decision but equally untestable on Hetzner Cloud today. Enabling Secure Boot on Hetzner's dedicated/Robot line is technically possible but explicitly unsupported by Hetzner and breaks their Rescue System / `installimage` auto-installer recovery path (a real operational cost, not just a setup cost). Revisit if the deployment target or the in-scope threat model changes. See §4.6. |
| **`SHIM_IPC_PATH` passed via environment variable** | Closed | Eliminated by the socketpair fd-authority model. There is no longer a socket path env var or a listening socket to redirect. See §4.6. |
| **Agent WS actor identity is caller-supplied** | Medium | The agent WS path accepts `actor_id` from the URL query string, verified only by possessing the `join_token`. The join_token is randomly generated (UUID v4, 122-bit) and now hashed at rest (SHA-256), so token possession implies controlled issuance — but the actor_id is not cryptographically bound to any specific identity. A valid join_token holder can claim any actor_id. Fix: issue join tokens per-actor (bind at issuance time); or enforce sp_token for all WS connections. |
| **join_token in WS URL query parameter** | Low | The raw join_token is included in the WS upgrade URL (`?token=...`), making it visible in proxy access logs and browser history. Cannot be moved to `Authorization: Bearer` header in browsers (browser WS API limitation). Mitigations in place: (1) token is hashed at rest so DB exposure does not reveal bearer value; (2) token is stored in `sessionStorage`, not `localStorage`, so it clears on tab close and is not accessible to cross-origin scripts via storage events. Recommended path: short-lived WS ticket system — authenticated HTTP call issues a 30-second single-use nonce, nonce used in WS URL. |
| **`NEXT_PUBLIC_ACTOR_ID` in frontend** | Low | Multiple frontend components fall back to `process.env.NEXT_PUBLIC_ACTOR_ID` when no OIDC session exists. In production with OIDC enforced this is never reached; in dev deployments it is a static identity. Pending: full UX audit to replace the static fallback with a mandatory OIDC flow or a login-prompt input; deferred to the SaaS frontend walkthrough. |
| **Meta-tool REST calls bypass shim audit trail** | Low | `register_methods()` and all meta-tool requests (`solarplex_post_message`, `solarplex_add_context`, artifact reads/writes) go directly from the adapter to the server via `reqwest`. The shim has no visibility into these calls and records no audit entry for them. Lower-risk (no exec capability; server enforces cap permissions), but creates an asymmetric audit picture: exec calls are fully logged; meta calls are not. |
| **No rate limiting on approval creation from adapter** | Low | A compromised or malfunctioning adapter can flood the shim with `Propose` messages, each resulting in a `create_approval_req()` call to the server. No per-session rate limit exists. Add: per-adapter per-session approval creation rate limit in the shim. |
| **Adapter and guardian not restarted on crash** | Low | The shim spawns both child processes once at startup but does not monitor their health. If the adapter or guardian crashes, the sidecar stack is effectively dead until the shim is restarted. Add: a supervision loop that re-spawns and re-handshakes on child exit. |
| **ShimClient 90-second proposal timeout can hold connections** | Info | The adapter's `ShimClient::propose()` waits up to 90 seconds for a `ProposalDecision`. A slow human (normal) or a pathological shim (abnormal) holds the MCP connection and the pending-map slot for the full duration. |
| **Scout manifest is heuristic, not authoritative** | Info | The ring-2 scout runs `strace -f` on a speculative execution; strace can miss effects from dynamic library loading, sub-shell tricks, or pre-fork state. The sandbox policy is derived from this heuristic. Documented in §4.4. |
| **Implemented** | | |
| IPC channels | Implemented | All channels use Unix **socketpairs** created by the shim before exec-ing each child. One end is `dup2`'d to a well-known fd (fd 3 = adapter, fd 4 = guardian) in the child's pre-exec hook. Fd possession is the sole authority proof — the kernel enforces that only a direct descendant of the spawning process holds the fd. No listening socket, no discoverable path, no channel secret env var, and no `SO_PEERCRED` PID check. Both children immediately set `O_CLOEXEC` on their authority fd so bwrap/MCP subprocesses cannot inherit it. Previous three-layer model (path isolation + SO_PEERCRED + ChannelHello secret) is replaced by this single structural guarantee. |
| Guardian "degraded" path | Implemented | Default is fail-closed: `verify_and_fetch()` returning `Err` causes an error response. Since the guardian fetches the command from the server in the same call, an unreachable server means no command to execute — fail-closed is enforced structurally. `SOLARPLEX_GUARDIAN_FAIL_OPEN=1` exists for dev but has no execution-path effect (changes log level only). |
| Guardian verification URL + IDOR | Implemented | Guardian calls `GET /api/approvals/{id}` with `X-Session-Id` and `X-Actor-Id` headers. Server verifies: (1) actor is a member of the stated session; (2) approval belongs to that session; (3) returns `{ decision, approved_command, declared_effects }`. Cross-session IDOR is blocked at the membership check. |
| Approval REST endpoint authentication | Implemented | `POST /api/approvals/:id/vote` requires `Authorization: Bearer <sp_token>`; actor_id is derived server-side from the validated token; request-body actor_id is ignored. `GET /api/approvals/pending` also prefers Bearer auth (query-param fallback is deprecated). `GET /api/approvals/:id/resolution`, `PATCH /:id/scout`, `PATCH /:id/execution`, `PATCH /:id/declared-effects` all require `X-Session-Id` + `X-Actor-Id` headers with session membership validation. |
| Ring-2 sandbox enforcement | Implemented | Default is fail-closed on Linux: if bwrap is not found, the guardian refuses to execute. `SOLARPLEX_ALLOW_UNSANDBOXED=1` is the explicit opt-out (development only; not safe for production). Non-Linux platforms also fail closed under the same opt-out flag. Previous behaviour (`SOLARPLEX_REQUIRE_SANDBOX` as opt-in) is removed. |
| Token storage at rest | Implemented | `sp_token` and `join_token` are stored as SHA-256 hex digests in the database (`human_sessions.id` and `sessions.join_token`). Raw bearer values are never persisted; only the hash enters the DB. `join_token` is returned to the API caller once (at session creation) and not again. Comparisons use constant-time folded XOR. |
| Frontend token storage | Implemented | join_token moved from `localStorage` (XSS-persistent, cross-tab) to `sessionStorage` (tab-scoped, cleared on close) in both frontend write sites (`components/NewSessionDrawer.tsx`, `app/sessions/[id]/page.tsx`). A third site, `app/sessions/new/page.tsx`, was fixed the same way at the time but has since been deleted as a redundant route — NewSessionDrawer is the only session-creation UI now. |

### 11.2 Pre-existing gaps (unchanged)

| Gap | Severity | Mitigation / Plan |
|---|---|---|
| **Open** | | |
| No per-event ACL (observers see all) | Medium | Cap DAG extension post-OIDC |
| `session_memberships.role` derived from cap DAG (step 2) | Low | Add `cap_id FK` on `session_memberships`; derive role from cap permissions at query time; blocked on defining canonical permission sets |
| Artifact scanning: no embedding model for semantic similarity | Low | TLSH covers syntactic similarity; semantic clustering (embedding-based) deferred until embedding API integrated |
| Artifact scanning: no manual verdict override UI | Low | `verdict_override` field exists in DB; must be set directly; UI deferred |
| CMS baseline resets on server restart | Low-info | Count-Min Sketch is in-memory only; re-learns baseline after 500 samples post-restart |
| `sp_token` transmitted in URL fragment | Low | Fragment is not sent to server or in referer; acceptable for v1 |
| OIDC discovery cached indefinitely | Low | Restart required to pick up provider key rotation; add TTL refresh |
| Seatbelt misses encoded/indirect secrets | Low-info | Documented; primary defense is opt-in |
| `who-can` query unrestricted (any caller) | Info | Add session membership check on query caller |
| Scout category routing unimplemented | Info | All jobs route to default pool; category tags are an extension point for cap metadata or tool-name policy |
| Scout observation unavailable outside Linux | Known limitation | `sandbox_backend: "none"` on macOS/Windows; filesystem snapshot diff still runs. macOS `dtruss` requires root; deferred. |
| **Implemented** | | |
| Legacy WS path (tokenless, raw `actor_id`) | Implemented | Hard 401 gate in `ws_handler`: `join_token` required when `sp_token` absent; no unauthenticated membership path remains (§3.3) |
| Untrusted plumb dispatch not gated | Implemented | `--untrusted` flag + `requires_trust` per rule; user rules and `ask/`, `act/`, `actor/` blocked on untrusted path; `.desktop` handler always passes `--untrusted` (§6) |
| Artifact content injection (prompt injection via artifact) | Implemented | Aho-Corasick phrase filter (14 patterns, O(n) sync path); SHA-256 verdict banner at read/create time; YARA-X + TLSH async background scan; Count-Min Sketch anomaly scoring; family reputation DB (§7) |
| Epoch-based cap revocation | Implemented | Migration 011; `POST /api/sessions/:id/epoch/revoke`; drain-bounded fencing; `EpochAdvanced` broadcast (§4.1) |
| Post-approval args-swap (adapter trust gap) | Implemented | ORB object adapter (§4.2); execution receipts bind `(cap_id, method, args)` server-side; adapter executes server's canonical args verbatim |
| Single-process trust gap (adapter self-approval) | Implemented | Three-process split (§4.6): adapter proposes only; shim gates; guardian independently verifies with server before every execution. No single process holds both decision authority and execution capability. |
| Shim cap-node sealed against in-process tampering | Implemented | `crates/shim/src/sealed.rs`: `mmap` → `mprotect(PROT_READ)` → `mseal()` (Linux 6.10+, graceful WARN-and-degrade on older kernels — same posture as IMA/dm-verity above). Applied to `Config`'s `Identity` (`session_id`/`actor_id`/`cap_id`/`permissions` — the shim's own local cap-DAG node; see §4.3) and `Policy`'s standing-policy cache, both written once at shim startup and read for the rest of the process's life. Closes the case where a memory-corruption bug in the shim — the one process this document designates as trusted (§2) — silently rewrites its own authority-adjacent state in place; defense in depth alongside, not a replacement for, the server's independent re-validation of `cap.permissions` on the ORB path. |
| seccomp-notify `ADDFD` grant path (was: non-functional, High-severity gap) | Implemented | Root cause found and fixed: `SECCOMP_ADDFD_FLAG_SEND` was `1 << 0` (the actual value of `SECCOMP_ADDFD_FLAG_SETFD`, a *different* flag), not the real `1 << 1`, confirmed against a fresh fetch of `include/uapi/linux/seccomp.h`. With the wrong bit set and `newfd: 0` always passed, every call was silently interpreted as "install at fd 0 specifically," never atomically responding to the notification — exactly matching the observed hang. Fixed in `crates/guardian/src/seccomp_ffi.rs`, with a regression test (`addfd_send_flag_is_not_setfd`) so this can't silently reoccur. A second, distinct bug surfaced once the hang was gone: `handle_notification` always opened the granted path read-only (`File::open`), so a declared *write* effect's injected fd failed with an I/O error the moment the tracee tried to write through it. Fixed by resolving the actual requested open mode from the notified syscall's own flags (`openat`'s flags register, or `openat2`'s `open_how.flags` behind a pointer) and opening with matching `OpenOptions` (`crates/guardian/src/notify.rs`). Verified end-to-end on a real kernel (Hetzner box, same 7.0.0-29-generic kernel as earlier validation): all 5 scenarios pass — declared write actually lands, undeclared write is denied by Landlock, undeclared read still works, `io_uring_setup` still hard-fails via the classic denylist, and a delete against a write-only-declared path correctly falls through to Landlock denial. `unlink`/`rename*` still have no real "open mode" concept and ADDFD's fd-number response value is semantically questionable for those specifically (not exercised by current test scenarios) — noted in `resolve_and_authorize`'s doc comment as a follow-up, not silently ignored. |
| `solarplex_exec` Ring-2 divergence check (was: structural no-op, empty pre_snap/post_snap) | Implemented | The guardian now snapshots `DeclaredEffects`' paths itself, immediately before/after the sandboxed exec — the guardian's own process has the real filesystem view the command actually touched, which the adapter (a different process, one hop downstream) never had. `GuardianResponse`/`ExecResultIpc` carry `pre_snap`/`post_snap`, propagated through to `ExecDoneNotice` exactly as this row's earlier "Fix:" note proposed. `protocol::ipc::snapshot_paths` extracted as a shared helper (previously duplicated only in the sidecar). |
| Ownership transfer disconnected from cap DAG | Implemented | Migration 013; `transfer()` algebra (§4.3); `session_members.role` demoted to display label; migration plan in §4.3 |
| Stale-state writes (agent lands on outdated artifact) | Implemented | Ring-0 CAS (§4.4): Postgres atomic H_before fence; proposals cannot commit against stale state |
| File-write content swap post-approval | Partial (detection) | Ring-1 authorize-and-attest (§4.4): receipt arg-binding with H_before/H_after; attestation; `hash_mismatch = true` = security event. Prevention impossible at POSIX layer. |
| Shell command effects opaque at approval time | Implemented (prevention + detection) | Ring-2 learning-mode scout (§4.4): strace traces `openat/unlinkat/renameat/connect/execve`; per-path `FileOps {create,write,delete,rename}` promoted to `DeclaredEffects` (union policy) before human votes; bwrap namespace + per-op landlock `AccessFs` flags + seccomp BPF denylist enforce at execution time; `manifest_diverged` flags divergence. |
| Unbounded scout concurrency (fork-bomb risk) | Implemented | `ScoutPool` bounded issue pool (§4.4): per-category sub-pools with fixed worker counts + queue depth; queue-full degrades gracefully |
| Cross-session `reroot_caps()` reparenting | Implemented | Session-scoped WHERE clause + DB trigger `enforce_token_epoch_coherence` (§4.5) |
| Cap field mutation post-issue | Implemented | DB trigger `enforce_token_field_immutability` blocks UPDATE of permissions/epoch/stratum (§4.5) |
| No rate limiting on OIDC endpoints | Implemented | `GlobalRateLimitKey::OidcAttempt`, keyed by client IP (the only identity available pre-authentication), gates both `oidc_start` and `oidc_callback` at 20/60s. IP is read from the raw TCP peer by default; `X-Forwarded-For` is only trusted when `TRUST_PROXY_HEADERS=1` is explicitly set, so a caller cannot spoof the header to dodge the limit unless the deploy has actually opted into trusting a reverse proxy for it. |
| Rate limiting had large coverage gaps | Implemented | Extended both tiers: session-scoped `RateLimitKey` gained `ArtifactMutate`, `ApprovalVote`, `CrossSessionDelegate`, `ManifestPatch`, `SessionLinkMutate`, `SessionRemoteMutate`, `MembershipGrant`, and `AuthorityImport`; global `GlobalRateLimitKey` gained `SessionCreate` and `InviteRedeemAttempt` alongside the existing `ActorCreate`. Every mutating route flagged in the pre-launch audit is now gated. |
| `DATABASE_URL` silently fell back to `postgres://localhost/solarplex` | Implemented | Removed the fallback; the server now fails to start with a clear error if `DATABASE_URL` is unset, same posture as the OIDC config check beside it (`main.rs`). |
| CORS was fully permissive (`CorsLayer::permissive()`) | Implemented | Origin allowlist read from `CORS_ALLOWED_ORIGINS` (comma-separated), defaulting to `http://localhost:3000` only when unset so local dev keeps working without configuration. Methods and headers are left open; the origin check is the actual boundary a browser enforces. |
| No TLS termination and no graceful shutdown in the server process | Implemented | Optional in-process TLS via `axum-server` + rustls, enabled by setting both `TLS_CERT_PATH` and `TLS_KEY_PATH` (see `deploy/caddy/Caddyfile` for the reverse-proxy alternative). SIGTERM/SIGINT now trigger a graceful drain (30s grace period) instead of an immediate hard kill of in-flight HTTP and WS connections, on both the TLS and plain-HTTP paths. |
| No request body size or timeout limits | Implemented | `tower-http`'s `limit` and `timeout` features are now enabled: a 10 MiB request body cap and a 30s per-request timeout apply globally. The one legitimately long-lived request (the approval long-poll) already manages its own internal deadline (capped at 60s) well inside that window. |
| No database backup tooling | Implemented | `deploy/scripts/backup-postgres.sh`: `pg_dump -Fc` streamed directly into `restic backup --stdin` (never touches local disk), targeting Backblaze B2 via its S3-compatible API (path-style endpoint, restic's native `b2:` backend is deliberately avoided — weaker error handling upstream). Daily via `solarplex-backup.timer` (`solarplex-backup.service`), retention via `restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune`, failure alerts reuse the same webhook pattern as `solarplex-alert-watch.sh`. Credentials (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD`, B2 S3 application key) travel as a second, independent age-encrypted bundle (`backup-secrets.age`, delivered by the new `solarplex_backup` Ansible role) rather than growing the fixed `CredentialBundle` schema — backup credentials don't share the DB-password ratchet's rotation cadence. Restore path (`restic restore` + `pg_restore`) is documented in the script's own header comment but has not been exercised end-to-end; like the IMA/dm-verity tooling above, none of this has run against a real host or a real B2 bucket yet — no Linux target or B2 account was available in this dev environment. |
| Stdout-only logging, no error tracking | Implemented | Two independent pieces. **Logging**: `crates/server/src/main.rs`'s `tracing_subscriber` now emits JSON (`fmt::layer().json()`) instead of the default human-readable format, and `solarplex-alert-watch.sh` was updated to parse each line's `.level` field via `jq` instead of grepping formatted text — a real parse instead of a brittle text match. The `solarplex` Ansible role now sets `Storage=persistent` + `SystemMaxUse=1G` in `journald.conf` (default `Storage=auto` keeps the journal on tmpfs, wiped every reboot, unless `/var/log/journal` already exists). **Error tracking**: self-hosted GlitchTip (Sentry-protocol-compatible; chosen over Bugsink for its OSI-approved license and deployment maturity, over the Rust-native `rustrak` for the latter's apparent lack of any production track record) deployed as a 3-container `podman-compose` stack (`deploy/glitchtip/`, GlitchTip 6's own consolidated `all_in_one` image + Postgres + Valkey), bound to `127.0.0.1` only — not exposed publicly by default, that's a separate later decision. `crates/server`'s `sentry` crate (official Sentry Rust SDK, pointed at GlitchTip's DSN — no GlitchTip-specific crate needed) is wired as an additional `tracing_subscriber` layer, fully opt-in on `GLITCHTIP_DSN` being set and non-empty; error/panic capture only, no performance/APM tracing (`traces_sample_rate` left at its default 0.0). The DSN itself can't be provisioned automatically — GlitchTip generates it only after an operator manually creates an org+project in its UI — so it travels as a third independent age-encrypted artifact (`glitchtip-dsn.age`, same `encrypt-bytes`/`decrypt-bytes` mechanism as `backup-secrets.age`), and `solarplex.service` tolerates that file not existing yet (falls back to error tracking disabled) rather than failing to start. Same caveat as the rows above: none of this — the GlitchTip stack, the DSN delivery path, or the JSON log format against a real `jq`/journald pipeline — has been run against a real host; only structural/syntax review was possible in this dev environment. |

---

## 12. Cryptographic dependencies

| Primitive | Use | Implementation |
|---|---|---|
| PKCE S256 | OIDC code challenge | `openidconnect` crate (SHA-256) |
| ID token signature | OIDC provider trust | `openidconnect` JWK verification (RS256/ES256) |
| `sp_token` | Human session identity — raw ULID sent to client; SHA-256 hex stored in DB | `ulid` crate (80-bit random); `sha2::Sha256::digest` + `hex::encode` at create/lookup/revoke time |
| `join_token` | Agent attach — raw UUID v4 returned once at session creation; SHA-256 hex stored in DB; constant-time comparison at WS upgrade | `uuid::Uuid::new_v4()`; `sha2::Sha256::digest` + `hex::encode`; folded-XOR constant-time compare |
| SHA-256 (content hashing) | Write-proposal CAS fence; file-write attestation H_before/H_after; artifact reputation lookup key; token storage (sp_token, join_token) | `sha2` crate (`sha2::Sha256::digest`); `hex` crate for encoding |
| TLSH (fuzzy hash) | Artifact family clustering; locality-sensitive similarity; distance threshold 50 | `tlsh2 = { version = "1", features = ["diff"] }`; `TlshDefaultBuilder::build_from()`; 72-byte ASCII digest |
| Aho-Corasick (multi-pattern) | Artifact content phrase filter (prompt injection sanitization) | `aho-corasick = "1"`; case-insensitive; LeftmostFirst; compiled once into `OnceLock` |
| Count-Min Sketch (probabilistic) | N-gram anomaly scoring for novel injection patterns | 4×65536 `u32` table; FNV-1a per row; character trigrams; in `Mutex<CmsState>` in `AppState` |
| TLS | All transport | `rustls` (CLI), platform TLS (server) |
| HKDF-SHA256 | Static secret rotation ratchet and domain-separated credential derivation | `hkdf` + `sha2` crates; see §13.3 |
| X25519 + ChaCha20-Poly1305 | Multi-recipient encryption of the static credential bundle (`secrets.age`) | `age` crate 0.12, `armor` feature; see §13.2 |
| Fast-key-erasure RNG | Entropy source for each ratchet advance, resistant to retroactive state recovery | `fast-erasure-shake-rng` crate; see §13.3 |
| systemd-creds (TPM2) | Per-host age identity sealing | systemd `LoadCredentialEncrypted=`; see §13.4 |

No custom cryptography. Key material (client secrets, OIDC private keys) stays
server-side and is never transmitted to clients.

---

## 13. Secrets management (static credentials)

Distinct from the OIDC-issued and cap-derived material covered elsewhere in
this document, three credentials are external inputs the system cannot mint
at runtime: `DATABASE_URL`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET`.
Everything else the application uses (session tokens, join tokens, cap
material) is runtime-issued and self-rotating, and is out of scope here.

### 13.1 Design summary

The pipeline is five layers, each independently swappable:

| Layer | Responsibility | Implementation |
|---|---|---|
| 1. Inventory | What needs protecting | `DATABASE_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and nothing else |
| 2. Storage | Where the ciphertext lives | One multi-recipient `age`-encrypted blob (`secrets.age`), safe to commit to git |
| 3. Access | Who can decrypt | Hardware-backed age identities (operator token, per-host TPM-sealed key), plus one offline recovery key |
| 4. Delivery | How ciphertext reaches a host and becomes usable | Ansible pushes ciphertext only; systemd decrypts at service start into a runtime-only file |
| 5. Rotation | How credentials change over time without manual coordination | A one-way forward-secret ratchet |

Crates: `crates/secrets-ratchet` (layer 5, deliberately I/O-free),
`crates/secrets-store` (layers 2 and 3, age encryption written against
`age::Recipient`/`age::Identity` traits so hardware-backed identities are a
config choice rather than a code change), `crates/secrets-cli` (layer 4
glue, the only binary that touches disk on behalf of the other two). Deploy
artifacts: `deploy/systemd/solarplex.service`, `deploy/ansible/`.

### 13.2 Storage and access (layers 2, 3)

`secrets.age` holds a small JSON bundle of the three credentials, encrypted
with the `age` format to every current recipient at once (operator key,
recovery key, and eventually per-host keys). Multi-recipient encryption
means any one recipient's identity is independently sufficient to decrypt
the whole bundle; losing access to one identity does not require
re-encrypting for the others.

The file is safe to commit to git in the literal sense: without a matching
private identity, the ciphertext discloses nothing. Encryption is
authenticated, so a tampered file fails to decrypt instead of producing
corrupted plaintext. Recipient strings look like `age1...`; identity
strings look like `AGE-SECRET-KEY-1...`. Neither form, nor any real
credential value, appears anywhere in this repository; both live only in
operator-controlled hardware or Vault-encrypted host variables.

Access is intentionally never a bare identity file on a networked host.
Today:

- The operator identity and the offline recovery key are software X25519
  identities in the `age` sense, generated once and kept off any host that
  runs the application (an operator hardware token, and printed or safe
  storage for the recovery key).
- Each host's own identity is sealed to that host's TPM using systemd's own
  `systemd-creds`, not a plaintext file. See 13.4 for why this is enough
  without `secrets-cli` needing to shell out to an age hardware plugin
  itself.

`secrets-store`'s encrypt and decrypt functions are written against the
`age::Recipient` and `age::Identity` traits rather than a concrete key
type, specifically so a future move to a real age hardware plugin (YubiKey,
TPM plugin) is a change at the identity string's source, not a rewrite of
the encryption code.

### 13.3 Rotation (layer 5)

Rotation is a ratchet, not a re-generation: `state_{N+1}` is
`HKDF-SHA256(state_N concatenated with fresh_random, domain "chain")`.
Every credential for an epoch is derived from that epoch's state with a
distinct domain-separated context string (for example
`solarplex-db-password-v1`, `solarplex-oidc-secret-v1`), so a single advance
rotates every credential in lockstep, with one piece of state to protect
instead of one per credential.

Two properties matter for threat reasoning:

- **Backward secrecy.** HKDF is one-way, so possessing `state_{N+1}` does
  not let you recover `state_N` or anything derived from it. Retired state
  is explicitly zeroized (the `zeroize` crate), not merely left for the
  allocator to reuse.
- **Post-compromise security.** Each step mixes in fresh entropy in
  addition to the deterministic chain. Without that, knowing `state_N`
  would let you compute every future state too; the entropy is what makes
  the future unpredictable to someone who only has the past.

The fresh entropy comes from a fast-key-erasure RNG (a Keccak-based sponge
that zeroizes its own internal state after every output), not an ordinary
CSPRNG. This closes a narrower gap than the ratchet's own HKDF step: an
ordinary CSPRNG's internal state, if compromised later, can in principle be
used to reconstruct past outputs. A fast-key-erasure RNG cannot be run
backward even if its live state is captured immediately after use, so a
later compromise of the rotation process cannot retroactively reveal what
entropy fed a past ratchet step.

`RatchetState` has no `Clone`, a redacted `Debug` implementation, and
zeroizes on drop. The only way to get raw bytes out of it is a deliberate,
consuming `export_for_storage()` call, made immediately before encrypting
those bytes for persistence. That call is the one place the ratchet's own
state briefly exists as a plain byte array in memory, and it is documented
as such rather than hidden.

### 13.4 Delivery (layer 4)

Ansible's routine play transmits ciphertext (`secrets.age`) and config (the
systemd unit, the release binaries) only. It never sees a plaintext
credential or a plaintext age identity.

The one exception is a per-host, one-time bootstrap step, excluded from the
routine play and run only with an explicit tag: sealing that host's age
identity into `systemd-creds`, sourced from an Ansible Vault-encrypted
variable. The plaintext identity exists only transiently, inside the
encrypted SSH pipe, for the single moment it is piped into `systemd-creds
encrypt --with-key=tpm2`. It is never written unsealed to disk on the
target and never logged.

At service start, the unit's `ExecStartPre` reads that TPM-sealed identity
back out via `LoadCredentialEncrypted=`, uses it to decrypt `secrets.age`,
and writes the result to a file inside `RuntimeDirectory=` (tmpfs-backed,
created fresh on start and wiped on stop) before `EnvironmentFile=` loads
it for the main process. The decrypted credentials never touch persistent
disk.

This deliberately layers two different secret-protection mechanisms for
two different jobs rather than treating them as alternatives.
`LoadCredentialEncrypted=` is systemd's own TPM sealing, used only to
protect the one small per-host identity; `age` protects the larger,
shared, git-committed credential bundle that identity is one of several
recipients of. Building a custom age-TPM-plugin integration was considered
and set aside: systemd already provides an equivalent TPM-backed secret
store natively, and using it for the identity is simpler than
reimplementing that binding from scratch.

No long-lived secrets daemon or Unix-socket broker exists in this design.
With three static credentials, the operational cost of a broker (another
process to secure, another attack surface, another thing to keep running)
is not justified; `secrets-cli` runs once per rotation and once per service
start, then exits.

### 13.5 What this design does and does not protect against

**Protects against:**

- A leaked or stolen `secrets.age` file (a git history leak, a misdirected
  backup) discloses nothing without a matching identity.
- A compromised host only exposes that host's own TPM-sealed identity, not
  the operator or recovery identities, and not any other host's identity.
- A compromise discovered after a rotation cannot recover credentials from
  before that rotation (backward secrecy). A compromise discovered before a
  rotation does not let an attacker predict credentials issued after it
  (post-compromise security, via the fresh entropy mixed into each step).
- Ansible's own logs and the git history it operates against never contain
  a plaintext credential or identity, aside from the single, tagged,
  one-time bootstrap step.

**Does not protect against:**

- A process that has already decrypted credentials into memory, whether
  that is the running `solarplex-server` itself or the brief
  `secrets-cli decrypt` run. This is the same boundary every secrets
  manager has: decrypted material must exist in memory for the application
  to use it.
- A host's TPM-sealed identity is only as strong as that host's own TPM and
  boot integrity. A host compromised while running, not merely a stolen
  disk, can ask `secrets-cli` to decrypt using the credential the running
  system already has access to.
- Hardware-plugin identities (a YubiKey or TPM-backed age plugin
  specifically, as opposed to systemd's own TPM sealing described above)
  are not yet implemented in `secrets-cli`; `parse_identity` and
  `parse_recipient` only accept the software X25519 string form today. The
  trait-object design in `secrets-store` means adding plugin support later
  changes where identity strings come from, not the encryption or
  decryption code itself.
- Rotation is operator-invoked (`secrets-cli rotate`), not scheduled. There
  is no automatic rotation trigger, expiry warning, or alerting on decrypt
  failure yet.

### 13.6 Verification performed

`secrets-ratchet` (16 tests) and `secrets-store` (11 tests) both include
adversarial cases, not only round-trip correctness: wrong identity
rejected, a tampered ciphertext byte rejected, a truncated file rejected,
and an identity absent from a multi-recipient blob's recipient list
rejected. The ratchet suite additionally checks that derived credentials
cannot be fed back in as if they were chain state to reconstruct the next
epoch.

A live end-to-end run of `secrets-cli` (init, rotate, decrypt, rotate
again) confirmed that rotation actually changes the derived database
password and OIDC client secret, that an identity unrelated to the
recipient list is rejected by both the credential bundle and the ratchet
state file, and that a byte-tampered `secrets.age` on disk fails to
decrypt rather than producing corrupted output. The systemd unit was
checked with `systemd-analyze verify`; the Ansible role's YAML was checked
for syntax validity.
