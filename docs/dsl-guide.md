# splx DSL: User Guide

The `authority-dsl` library is a typed, cross-provider language for describing what a principal is allowed to do. It compiles to a canonical internal representation that can be normalized, verified, serialized, and lowered to platform enforcement mechanisms like Linux Landlock.

The serialized form is a small, self-describing wire format — "nothing that requires a running image to read back," in `serializer.lisp`'s own words — so an authority entry, delegation, or capability written here doesn't only mean something to the process that produced it. Anything that can parse the wire format can act on it. [Rust Consumers](#rust-consumers) covers the two that do today, both outside this Lisp system entirely.

---

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Quick Syntax Reference](#quick-syntax-reference)
3. [Resources](#resources)
4. [Operations](#operations)
5. [Conditions](#conditions)
6. [Delegation Graphs](#delegation-graphs)
7. [Parsing and Normalization](#parsing-and-normalization)
8. [Verification](#verification)
9. [Backends](#backends)
10. [Operational Checks](#operational-checks)
11. [Full Examples](#full-examples)
12. [Rust Consumers](#rust-consumers)

---

## Core Concepts

**Authority entry.** A single permission grant: a resource, a set of allowed operations on it, and optional conditions that narrow when the grant applies.

**Node.** A named principal with a list of authority entries. A node represents one participant's full capability set at a point in time.

**Delegation.** An edge from one node to another. The grantor attenuates: the grantee can only receive a subset of the grantor's authority, never more.

**Authority graph.** A directed acyclic graph of nodes and delegations. The graph is the unit of verification and transport.

**Provider.** The system that enforces a resource type. Current providers: `:linux-fs`, `:linux-net`, `:linux-pid`, `:ipc-fd`, `:http-ucan`, `:wasm`. Short aliases (`fs`, `net`, `pid`) are accepted everywhere and normalized to the canonical keyword.

---

## Quick Syntax Reference

```lisp
;; Single entry: what resource, what operations
(fs "/data/**" :read :write)

;; Net resource
(net "db.internal" :connect)

;; With conditions
(fs "/tmp/**" :read :write
    :ttl 3600
    :quorum 2)

;; Full capability form (used with define-capability)
(define-capability "payments-worker"
  :roots ("SHIM")
  :principals ("payments-worker")
  :version 1
  :authority
    ((fs "/data/payments/**" :read :write)
     (net "payments-api.internal" :connect)
     (pid :any :signal)))

;; Delegation from grantor to grantee
(define-capability "payments-agent"
  :roots ("payments-worker")
  :principals ("payments-agent")
  :derived-from payments-worker
  :authority
    ((fs "/data/payments/**" :read)))  ; subset of grantor
```

---

## Resources

Each resource belongs to one provider. The parser accepts both keyword and symbol forms.

### Filesystem (`fs`)

```lisp
(fs "/data/**" ...)          ; recursive glob (all files under /data)
(fs "/etc/config" ...)       ; exact path
(fs "/tmp/*" ...)            ; single-level wildcard (normalized to /tmp/**)
(fs "/" ...)                 ; root (normalized to /**)
```

Path normalization rules applied at parse time:
- Trailing slash stripped: `/data/` becomes `/data`
- Single star promoted to double: `/tmp/*` becomes `/tmp/**`
- Bare `/` becomes `/**`

### Network (`net`)

```lisp
(net "db.internal" ...)                   ; host only
(net "db.internal:5432" ...)              ; host:port
(net "*.internal" ...)                    ; wildcard subdomain
```

Host names are lowercased during normalization.

### Process (`pid`)

```lisp
(pid :any :signal)          ; signal any process
(pid :any :fork)            ; fork
(pid 1234 :signal)          ; signal specific PID
```

PID resources accept `:any` or an integer PID as the first argument, and a keyword operation as the second.

### IPC / file descriptor (`ipc`)

```lisp
(ipc :fd 3)                 ; pass fd 3
(ipc :fd :any)              ; pass any fd
```

### HTTP (`http`)

```lisp
(http "/api/**" :get :post) ; allow GET and POST to /api/**
```

---

## Operations

Operations are keywords. Available operations depend on the provider.

| Provider | Operations |
|---|---|
| `linux-fs` | `:read`, `:write`, `:exec`, `:create`, `:delete` |
| `linux-net` | `:connect`, `:bind`, `:accept` |
| `linux-pid` | `:signal`, `:fork`, `:wait` |
| `ipc-fd` | `:send`, `:recv` |
| `http-ucan` | `:get`, `:post`, `:put`, `:delete`, `:patch` |

The op-set is normalized: duplicates removed, remaining ops sorted alphabetically for a stable canonical form.

---

## Conditions

Conditions narrow when a grant applies. All are optional keyword arguments after the op list.

| Condition | Type | Meaning |
|---|---|---|
| `:ttl <seconds>` | integer | Token expires after this many seconds |
| `:quorum <n-or-role>` | integer or symbol | How many approvers (or which role) must sign off |
| `:single-use t` | boolean | Grant consumed after one use |
| `:audit t` | boolean | All uses must be logged |

Quorum can be:
```lisp
:quorum 2              ; any 2 approvers
:quorum guardian       ; the role named :guardian
:quorum guardian+human ; both roles required (parsed as a list)
```

When merging two grants on the same resource, conditions are combined conservatively: the higher TTL wins (more permissive), the lower quorum wins (more permissive), `single-use` requires both to be set, and `audit` requires both to be set.

---

## Delegation Graphs

The delegation graph is the primary data structure. Build one directly with the IR:

```lisp
(use-package :authority-dsl)

;; Create a graph
(let ((g (make-authority-graph)))

  ;; Add root node
  (graph-add-node g
    (make-instance 'cap-node
      :principal (make-principal "SHIM")
      :authority (list
        (make-instance 'authority-entry
          :resource (make-instance 'fs-resource
                      :path (path-glob "/data/**"))
          :ops      (op-set :read :write)))
      :root t))

  ;; Add worker node
  (graph-add-node g
    (make-instance 'cap-node
      :principal (make-principal "worker")
      :authority (list
        (make-instance 'authority-entry
          :resource (make-instance 'fs-resource
                      :path (path-glob "/data/**"))
          :ops      (op-set :read)))))

  ;; Add delegation: SHIM grants :read to worker
  (graph-add-delegation g
    (make-instance 'delegation
      :grantor   "SHIM"
      :grantee   "worker"
      :authority (list
        (make-instance 'authority-entry
          :resource (make-instance 'fs-resource
                      :path (path-glob "/data/**"))
          :ops      (op-set :read)))))

  g)
```

Or use the parser to build from DSL forms:

```lisp
(authority-dsl/parser:parse-graph
  '(graph
     (node "SHIM" :root t
       :authority ((fs "/data/**" :read :write)))
     (node "worker"
       :authority ((fs "/data/**" :read)))
     (delegation :grantor "SHIM" :grantee "worker"
       :authority ((fs "/data/**" :read)))))
```

---

## Parsing and Normalization

### Parsing

`authority-dsl/parser:parse-entry` parses a single entry s-expression:

```lisp
(parse-entry '(fs "/data/**" :read :write :ttl 3600))
; => #<AUTHORITY-ENTRY>
```

`authority-dsl/parser:parse-graph` parses a complete graph form.

### Normalization

After parsing, normalize to put everything in canonical order:

```lisp
(authority-dsl/normalizer:normalize-graph graph)
```

Normalization:
- Deduplicates and sorts ops within each entry
- Merges entries with the same canonical resource (union ops, conservative conditions)
- Sorts entries by provider then by resource path
- Applies path normalization rules (trailing slashes, single-star promotion)
- Lowercases host names

### Hashing

For signing or cache keys, normalize first, then hash:

```lisp
;; Without a hash function: returns the canonical string
(hash-graph graph)

;; With a hash function: returns hex string
(setf *hash-function*
      (lambda (s)
        ;; plug in any SHA-256 implementation
        (my-sha256-hex s)))
(hash-graph graph)
```

---

## Verification

The verifier checks that a delegation graph is internally consistent.

```lisp
(authority-dsl/verifier:verify-graph graph)
; => #<VERIFICATION-RESULT :ok t>  or  #<VERIFICATION-RESULT :ok nil :errors (...)>
```

What the verifier checks:
- Every delegation's grantor node exists
- Every delegation's grantee node exists
- No delegation grants more than the grantor holds (attenuation check)
- Root nodes are correctly marked
- No cycles

Check a single delegation:
```lisp
(verify-delegation delegation grantor-node grantee-node)
```

Check authority subset relationship:
```lisp
(authority-subset-p entry-a entry-b)
; => t if entry-a's authority is a subset of entry-b's
```

---

## Backends

Backends lower the IR to platform enforcement. Currently only the Linux backend is implemented.

### Linux (Landlock)

```lisp
(use-package :authority-dsl/backends/linux)

(let* ((normalized (normalize-graph graph))
       (ruleset    (lower-to-linux "worker" normalized)))
  ;; ruleset is a LANDLOCK-RULESET struct
  (landlock-ruleset-fs-rules ruleset)   ; list of LANDLOCK-FS-RULE
  (landlock-ruleset-net-rules ruleset)  ; list of LANDLOCK-NET-RULE
  (landlock-ruleset-pid-rules ruleset)  ; list of LANDLOCK-PID-RULE

  ;; Emit as s-expression (for debugging or serialization)
  (emit-landlock-sexp ruleset))
```

Each `landlock-fs-rule` has `:path` (string) and `:flags` (bitfield). Each `landlock-net-rule` has `:port` (integer) and `:flags`. The flags match Landlock ABI constants.

---

## Operational Checks

Runtime checks against a live capability set:

```lisp
(use-package :authority-dsl/operational)

;; Does the actor's current caps cover a required entry?
(scope-covers-p required-entry current-caps)

;; Check at form-definition time (macroexpand-time static check)
;; Raises STATIC-SCOPE-ERROR if the form requests resources outside the declared scope.
(with-static-scope (scope-entries)
  (body-form-that-uses-resources ...))
```

`static-scope-error` is a condition with `:message` and `:form` readers.

---

## Full Examples

### Read-only filesystem access

```lisp
(parse-entry '(fs "/var/log/**" :read))
```

### Multi-resource worker

```lisp
(parse-graph
  '(graph
     (node "SHIM" :root t
       :authority
         ((fs "/app/**"          :read :exec)
          (fs "/tmp/**"          :read :write)
          (net "api.internal"    :connect)
          (pid :any              :signal)))
     (node "worker"
       :authority
         ((fs "/app/**"          :read :exec)
          (fs "/tmp/worker/**"   :read :write)
          (net "api.internal"    :connect)))
     (delegation :grantor "SHIM" :grantee "worker"
       :authority
         ((fs "/app/**"          :read :exec)
          (fs "/tmp/worker/**"   :read :write)
          (net "api.internal"    :connect)))))
```

### Conditional grant with TTL and quorum

```lisp
(parse-entry
  '(fs "/secrets/**" :read
       :ttl 900
       :quorum guardian
       :single-use t))
```

### Verification and lowering

```lisp
(let* ((graph  (parse-graph my-graph-form))
       (normed (normalize-graph graph))
       (result (verify-graph normed)))
  (if (verification-result-ok result)
      (lower-to-linux "worker" normed)
      (error "graph invalid: ~a" (verification-result-errors result))))
```

---

## Rust Consumers

Everything above runs inside a Lisp image, so nothing on this page requires Solarplex's Rust runtime, or Solarplex at all, to be present. `authority-dsl/serializer` emits the wire format specifically so that stops being true only when something chooses to read it back. Two things do, both living in the main `solarplex` repository rather than here.

### `splx-ir` for reading the wire format

A minimal deserializer for exactly what `serializer.lisp` emits: entries, delegations, capabilities, effects/deltas, and saga receipts/logs. The graph/node/principal containers aren't wire types on the Lisp side either, so this crate doesn't model them. A consumer receives a stream of entries/delegations/capabilities and assembles its own local view. It re-verifies nothing: `authority-subset-p` and the rest of the attenuation lattice stay authoritative here, in `algebra.lisp`; the Rust side trusts what it's handed, the same way a client trusts a signed token rather than re-deriving it.

```rust
let value: splx_ir::SplxValue = wire_sexpr.parse()?;
match value {
    splx_ir::SplxValue::Capability(cap) => { /* ... */ }
    splx_ir::SplxValue::Delegation(d)   => { /* ... */ }
    // ...
}
```

### `db::authority_import` for executing it

The concrete consumer: it translates a parsed `AuthorityEntry` list into Solarplex's own capability model (`AuthorityArena`/`Authority`) and mints a real, attenuation-checked, revocable cap from it. A `(capability ...)` form with no `:derived-from` becomes a new root cap; a `(delegation ...)` form delegates from an existing one — either way it runs through the exact same invariants as a capability created from inside the app, because it *is* that same code path (`AuthorityArena::alloc` / `Authority::delegate`). This is deliberately not a new enforcement mechanism, and it does not touch `crates/guardian`'s live Landlock enforcement, which reads its own native `protocol::effects::DeclaredEffects` and stays that way.

Solarplex's cap model has no resource/op structure of its own (`permissions` is a flat list of opaque strings), so each `(resource, op)` pair in an entry becomes one permission string, `"{provider}:{resource}:{op}"`: `(fs "/data/**" :read :write)` becomes `linux-fs:/data/**:read` and `linux-fs:/data/**:write`.

Exposed at `POST /api/sessions/:id/authority` (Collaborator+, same authorization bar as epoch revocation):

```
POST /api/sessions/01K.../authority
Authorization: Bearer <sp_token>
Content-Type: application/json

{
  "sexpr": "(:capability :action :invoke :subject \"payments-worker\"
              :authority ((:entry :resource (:fs :path \"/data/payments/**\")
                            :ops (:read :write) :conditions nil))
              :derived-from nil :conditions nil :metadata nil)",
  "actor_id": "01K...",
  "ttl_secs": 3600
}
```

```json
{
  "cap_id": "01K...",
  "permissions": ["linux-fs:/data/payments/**:read", "linux-fs:/data/payments/**:write"],
  "expires_at": "2026-08-09T21:10:10Z",
  "stratum": 0
}
```

For a `(delegation ...)` import, pass `parent_cap_id` — the existing cap in this session to delegate from. `Authority::delegate`'s attenuation check applies exactly as it would to any in-app delegation, so the import can only narrow what `parent_cap_id` already holds here, never expand it, regardless of what the DSL source claims.

Neither consumer resolves the DSL's abstract principal names (`"SHIM"`, `"payments-worker"`, ...) to real Solarplex actor IDs — that's the caller's job, `actor_id`/`parent_cap_id` above are already-resolved Solarplex identifiers. This is the same division of labor `crates/intent` uses for the actor and session names it extracts from typed commands (see that crate's doc comment): the DSL describes *what*; resolving *who, in this particular running system* needs a real database and a real membership boundary, which is deliberately outside what either deserializer owns.

---

## Package Summary

| Package | Purpose |
|---|---|
| `authority-dsl/ir` | Core structs: authority-entry, cap-node, authority-graph, delegation |
| `authority-dsl/algebra` | Op-set operations, authority-subset-p |
| `authority-dsl/parser` | Parse DSL s-expressions to IR |
| `authority-dsl/normalizer` | Canonical form, deduplication, hashing |
| `authority-dsl/verifier` | Attenuation and consistency checks |
| `authority-dsl/backends/linux` | Lower to Landlock ruleset structs |
| `authority-dsl/operational` | Runtime scope checks, static-scope-error |

Load the complete system:

```lisp
(asdf:load-system :authority-dsl)
```

Run all tests:

```lisp
(asdf:test-system :authority-dsl)
```
