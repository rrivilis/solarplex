(defpackage #:authority-dsl/tests/e2e
  (:use #:cl
        #:authority-dsl/algebra
        #:authority-dsl/ir
        #:authority-dsl/parser
        #:authority-dsl/normalizer
        #:authority-dsl/verifier))

(in-package #:authority-dsl/tests/e2e)

;;; ── Minimal runner ───────────────────────────────────────────────────────────

(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (label form)
  `(if ,form
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a~%" ,label))))

(defmacro check-error (label condition-type &body body)
  `(if (handler-case (progn ,@body nil)
         (,condition-type () t)
         (error () nil))
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a (wrong or no error)~%" ,label))))

(defmacro check-no-error (label &body body)
  `(if (handler-case (progn ,@body t)
         (error (e) (format t "  NOTE  unexpected error: ~a~%" e) nil))
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a~%" ,label))))

(defun make-fs (path &rest ops)
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource :path (path-glob path))
                 :ops (apply #'op-set ops)))

(defun make-net (host &rest ops)
  (make-instance 'authority-entry
                 :resource (make-instance 'net-resource :host host)
                 :ops (apply #'op-set ops)))

(defun make-pid (ref &rest ops)
  (make-instance 'authority-entry
                 :resource (make-instance 'pid-resource :ref ref)
                 :ops (apply #'op-set ops)))

(defun make-wasm (module &rest ops)
  (make-instance 'authority-entry
                 :resource (make-instance 'wasm-resource :module module)
                 :ops (apply #'op-set ops)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 1. PER-PROVIDER LATTICE CORRECTNESS
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-fs-lattice ()
  (format t "~%── fs lattice ──~%")
  (check "/data/foo/** ⊑ /data/**"
         (authority-subset-p (make-fs "/data/foo/**" :read)
                             (make-fs "/data/**"     :read)))
  (check "/data/** ⊑ /**"
         (authority-subset-p (make-fs "/data/**" :read)
                             (make-fs "/**"      :read)))
  (check "/data/** ⋢ /data/foo/**  (broader path not ⊑ narrower)"
         (not (authority-subset-p (make-fs "/data/**"     :read)
                                  (make-fs "/data/foo/**" :read))))
  (check "/other/** ⋢ /data/**  (disjoint paths)"
         (not (authority-subset-p (make-fs "/other/**" :read)
                                  (make-fs "/data/**"  :read))))
  (check ":read ⊑ :read/:write (op subset)"
         (authority-subset-p (make-fs "/data/**" :read)
                             (make-fs "/data/**" :read :write)))
  (check ":read/:write ⋢ :read  (op escalation)"
         (not (authority-subset-p (make-fs "/data/**" :read :write)
                                  (make-fs "/data/**" :read))))
  (check "/data/foo/** :write ⋢ /data/** :read  (op escalation across path)"
         (not (authority-subset-p (make-fs "/data/foo/**" :write)
                                  (make-fs "/data/**"     :read)))))

(defun test-net-lattice ()
  (format t "~%── net lattice ──~%")
  (let ((parent-any (make-instance 'authority-entry
                                   :resource (make-instance 'net-resource :host "*")
                                   :ops (op-set :connect)))
        (child-host (make-net "example.com" :connect))
        (child-diff (make-net "evil.com" :connect))
        (parent-host (make-net "example.com" :connect :bind))
        (child-connect-only (make-net "example.com" :connect)))
    (check "example.com ⊑ * (wildcard host)"
           (authority-subset-p child-host parent-any))
    (check "evil.com ⋢ example.com (host mismatch)"
           (not (authority-subset-p child-diff parent-host)))
    (check ":connect ⊑ :connect/:bind"
           (authority-subset-p child-connect-only parent-host))
    (check ":connect/:bind ⋢ :connect"
           (not (authority-subset-p parent-host child-connect-only)))))

(defun test-net-port-lattice ()
  (format t "~%── net port range lattice ──~%")
  (let ((parent (make-instance 'authority-entry
                               :resource (make-instance 'net-resource
                                                        :host "example.com"
                                                        :port-min 1024 :port-max 65535)
                               :ops (op-set :connect)))
        (child-narrow (make-instance 'authority-entry
                                     :resource (make-instance 'net-resource
                                                              :host "example.com"
                                                              :port-min 8080 :port-max 8080)
                                     :ops (op-set :connect)))
        (child-wide (make-instance 'authority-entry
                                   :resource (make-instance 'net-resource
                                                            :host "example.com"
                                                            :port-min 0 :port-max 65535)
                                   :ops (op-set :connect))))
    (check "[8080,8080] ⊑ [1024,65535]"
           (authority-subset-p child-narrow parent))
    (check "[0,65535] ⋢ [1024,65535]  (wider port range escalation)"
           (not (authority-subset-p child-wide parent)))))

(defun test-pid-lattice ()
  (format t "~%── pid lattice ──~%")
  (let ((parent-any (make-pid :any :signal))
        (child-1234 (make-pid 1234 :signal))
        (child-5678 (make-pid 5678 :signal))
        (parent-1234 (make-pid 1234 :signal :kill)))
    (check "pid:1234 ⊑ pid:any"
           (authority-subset-p child-1234 parent-any))
    (check "pid:5678 ⋢ pid:1234  (different pid)"
           (not (authority-subset-p child-5678 parent-1234)))
    (check "pid:1234 :signal ⊑ pid:1234 :signal/:kill"
           (authority-subset-p (make-pid 1234 :signal) parent-1234))
    (check "pid:1234 :kill ⋢ pid:1234 :signal  (op escalation)"
           (not (authority-subset-p (make-pid 1234 :kill) (make-pid 1234 :signal))))))

(defun test-ipc-fd-lattice ()
  (format t "~%── ipc-fd lattice ──~%")
  (let ((parent-any (make-instance 'authority-entry
                                   :resource (make-instance 'ipc-fd-resource :fd :any)
                                   :ops (op-set :send :recv)))
        (child-fd3  (make-instance 'authority-entry
                                   :resource (make-instance 'ipc-fd-resource :fd 3)
                                   :ops (op-set :send)))
        (child-fd4  (make-instance 'authority-entry
                                   :resource (make-instance 'ipc-fd-resource :fd 4)
                                   :ops (op-set :send))))
    (check "fd:3 ⊑ fd:any"
           (authority-subset-p child-fd3 parent-any))
    (check "fd:4 :send ⊑ fd:any :send/:recv"
           (authority-subset-p child-fd4 parent-any))
    (check "fd:3 ⋢ fd:4  (different fd)"
           (not (authority-subset-p child-fd3
                                    (make-instance 'authority-entry
                                                   :resource (make-instance 'ipc-fd-resource :fd 4)
                                                   :ops (op-set :send)))))))

(defun test-wasm-lattice ()
  (format t "~%── wasm lattice ──~%")
  (let ((parent-any (make-wasm "*" :instantiate :execute))
        (child-mod  (make-wasm "my-module" :execute))
        (other-mod  (make-wasm "evil-module" :instantiate)))
    (check "my-module ⊑ * (wildcard module)"
           (authority-subset-p child-mod parent-any))
    (check "evil-module :instantiate ⊑ * :instantiate/:execute"
           (authority-subset-p other-mod parent-any))
    (check "my-module ⋢ other-module"
           (not (authority-subset-p child-mod (make-wasm "other-module" :execute))))
    (check ":instantiate/:execute ⋢ :execute  (op escalation)"
           (not (authority-subset-p (make-wasm "m" :instantiate :execute)
                                    (make-wasm "m" :execute))))))

(defun test-condition-lattice ()
  (format t "~%── condition lattice ──~%")
  (let* ((base-r  (make-instance 'fs-resource :path (path-glob "/data/**")))
         (base-ops (op-set :read))
         (no-cond  (make-instance 'authority-entry :resource base-r :ops base-ops))
         (ttl-3600 (make-instance 'authority-entry :resource base-r :ops base-ops
                                  :conditions (condition-set :ttl 3600)))
         (ttl-1800 (make-instance 'authority-entry :resource base-r :ops base-ops
                                  :conditions (condition-set :ttl 1800)))
         (ttl-7200 (make-instance 'authority-entry :resource base-r :ops base-ops
                                  :conditions (condition-set :ttl 7200)))
         (single   (make-instance 'authority-entry :resource base-r :ops base-ops
                                  :conditions (condition-set :single-use t))))
    (check "no parent condition: any child ok"
           (authority-subset-p ttl-3600 no-cond))
    (check "parent ttl=3600: child ttl=1800 ok (tighter)"
           (authority-subset-p ttl-1800 ttl-3600))
    (check "parent ttl=3600: child ttl=7200 violates (relaxed)"
           (not (authority-subset-p ttl-7200 ttl-3600)))
    (check "parent single-use: child without single-use violates"
           (not (authority-subset-p no-cond single)))
    (check "parent single-use: child with single-use ok"
           (authority-subset-p single single))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 2. LEAKAGE SCENARIOS
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-cross-provider-rejection ()
  (format t "~%── cross-provider rejection ──~%")
  ;; The verifier must NEVER treat an fs entry as covering a net entry or vice versa.
  ;; Cross-provider authority amplification is a known semantic gap (documented in
  ;; THREAT_MODEL §11.1), but syntactic cross-provider subset must always be NIL.
  (check "fs :read ⋢ net :connect  (cross-provider)"
         (not (authority-subset-p (make-fs "/proc/net/**" :read)
                                  (make-net "example.com" :connect))))
  (check "net :connect ⋢ fs :read  (cross-provider reversed)"
         (not (authority-subset-p (make-net "example.com" :connect)
                                  (make-fs "/**" :read))))
  (check "pid :signal ⋢ ipc-fd :send  (cross-provider)"
         (not (authority-subset-p (make-pid :any :signal)
                                  (make-instance 'authority-entry
                                                 :resource (make-instance 'ipc-fd-resource :fd :any)
                                                 :ops (op-set :send)))))
  (check "wasm :execute ⋢ fs :execute  (cross-provider)"
         (not (authority-subset-p (make-wasm "*" :execute)
                                  (make-fs "/**" :execute)))))

(defun test-escalation-via-delegation ()
  (format t "~%── graph escalation detection ──~%")
  ;; Build a graph where the shim has narrow authority and the adapter tries
  ;; to claim broader authority.  Verify-graph must detect every variant.
  (labels ((bad-graph (shim-entries adapter-entries delegated-entries)
             (let* ((g (make-authority-graph))
                    (root (make-instance 'root-authority :kind :ambient-os :provider :linux))
                    (sp (make-instance 'principal :id "shim"))
                    (ap (make-instance 'principal :id "adapter"))
                    (sn (make-instance 'cap-node :principal sp :authority shim-entries :root root))
                    (an (make-instance 'cap-node :principal ap :authority adapter-entries))
                    (e  (make-instance 'delegation :grantor "shim" :grantee "adapter"
                                                   :authority delegated-entries)))
               (graph-add-node g sn)
               (graph-add-node g an)
               (graph-add-delegation g e)
               g)))
    ;; Broader path escalation
    (let ((g (bad-graph (list (make-fs "/data/session/**" :read))
                        (list (make-fs "/data/**"         :read))
                        (list (make-fs "/data/**"         :read)))))
      (check "path escalation detected"
             (not (result-ok-p (verify-graph g)))))
    ;; Write op escalation
    (let ((g (bad-graph (list (make-fs "/data/**" :read))
                        (list (make-fs "/data/**" :read :write))
                        (list (make-fs "/data/**" :read :write)))))
      (check "op escalation detected"
             (not (result-ok-p (verify-graph g)))))
    ;; Port range escalation
    (let* ((narrow (make-instance 'authority-entry
                                  :resource (make-instance 'net-resource
                                                           :host "example.com"
                                                           :port-min 8080 :port-max 8080)
                                  :ops (op-set :connect)))
           (wide   (make-instance 'authority-entry
                                  :resource (make-instance 'net-resource
                                                           :host "example.com"
                                                           :port-min 0 :port-max 65535)
                                  :ops (op-set :connect)))
           (g (bad-graph (list narrow) (list wide) (list wide))))
      (check "port range escalation detected"
             (not (result-ok-p (verify-graph g)))))
    ;; TTL relaxation
    (let* ((tight (make-instance 'authority-entry
                                 :resource (make-instance 'fs-resource :path (path-glob "/data/**"))
                                 :ops (op-set :read)
                                 :conditions (condition-set :ttl 1800)))
           (loose (make-instance 'authority-entry
                                 :resource (make-instance 'fs-resource :path (path-glob "/data/**"))
                                 :ops (op-set :read)
                                 :conditions (condition-set :ttl 7200)))
           (g (bad-graph (list tight) (list loose) (list loose))))
      (check "TTL relaxation escalation detected"
             (not (result-ok-p (verify-graph g)))))))

(defun test-valid-narrow-delegation ()
  (format t "~%── valid narrow delegations ──~%")
  ;; All of these should pass — they are genuine subset delegations.
  (labels ((ok-graph (shim-entry delegated-entry)
             (let* ((g (make-authority-graph))
                    (root (make-instance 'root-authority :kind :ambient-os :provider :linux))
                    (sp (make-instance 'principal :id "shim"))
                    (ap (make-instance 'principal :id "adapter"))
                    (sn (make-instance 'cap-node :principal sp
                                       :authority (list shim-entry) :root root))
                    (an (make-instance 'cap-node :principal ap
                                       :authority (list delegated-entry)))
                    (e  (make-instance 'delegation :grantor "shim" :grantee "adapter"
                                       :authority (list delegated-entry))))
               (graph-add-node g sn)
               (graph-add-node g an)
               (graph-add-delegation g e)
               (verify-graph g))))
    (check "narrow path + same ops: valid"
           (result-ok-p (ok-graph (make-fs "/data/**"     :read :write)
                                  (make-fs "/data/sess/**" :read))))
    (check "same path + fewer ops: valid"
           (result-ok-p (ok-graph (make-fs "/data/**" :read :write :execute)
                                  (make-fs "/data/**" :read))))
    (check "pid any → specific pid: valid"
           (result-ok-p (ok-graph (make-pid :any :signal)
                                  (make-pid 42   :signal))))
    (check "wasm * → specific module: valid"
           (result-ok-p (ok-graph (make-wasm "*"        :instantiate :execute)
                                  (make-wasm "safe-mod" :execute))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 3. PARSER HOOK BUGS + INJECTION
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-parser-safety ()
  (format t "~%── parser safety ──~%")
  ;; Parser uses READ — we must ensure that the s-expression shapes we parse
  ;; cannot trigger arbitrary side effects.  The parser is READ-then-validate,
  ;; not EVAL.  These tests confirm that malformed shapes produce parser-error,
  ;; not silent success or arbitrary CL execution.
  (check-error "missing top-level form" parser-error
    (parse-authority-graph "(not-authority-graph)"))
  (check-error "missing :id in root" parser-error
    (parse-authority-graph
     "(authority-graph (roots (root :kind :ambient-os :provider :linux)))"))
  (check-error "missing :kind in root" parser-error
    (parse-authority-graph
     "(authority-graph (roots (root :id \"shim\" :provider :linux)))"))
  (check-error "unknown provider" parser-error
    (parse-authority-graph
     "(authority-graph (principals (principal :id \"a\"
                                   :authority ((badprovider /foo/** :read)))))"))
  (check-error "unknown top-level clause" parser-error
    (parse-authority-graph
     "(authority-graph (inject-evil foo))"))
  ;; Syntactically valid but semantically empty — should not error.
  (check-no-error "empty graph is valid"
    (parse-authority-graph "(authority-graph)"))
  ;; Injected principal with no authority — valid parse.
  (check-no-error "principal with no authority"
    (parse-authority-graph
     "(authority-graph (principals (principal :id \"a\" :authority nil)))")))

(defun test-parser-sugar-expansion ()
  (format t "~%── parser sugar expansion ──~%")
  ;; Confirm that provider aliases all resolve to canonical IR types.
  (let* ((g (parse-authority-graph
              "(authority-graph
                (principals
                 (principal :id \"p\"
                            :authority ((fs /data/** :read)
                                        (net example.com :connect)
                                        (pid :any :signal)
                                        (ipc-fd 3 :send)
                                        (http /api/** :get)
                                        (wasm my-mod :execute)))))"))
         (entries (node-authority (graph-node-for g "p"))))
    (check "6 entries parsed" (= 6 (length entries)))
    (check "fs → :linux-fs"
           (eq :linux-fs (resource-provider (entry-resource (first entries)))))
    (check "net → :linux-net"
           (eq :linux-net (resource-provider (entry-resource (second entries)))))
    (check "pid → :linux-pid"
           (eq :linux-pid (resource-provider (entry-resource (third entries)))))
    (check "ipc-fd → :ipc-fd"
           (eq :ipc-fd (resource-provider (entry-resource (fourth entries)))))
    (check "http → :http-ucan"
           (eq :http-ucan (resource-provider (entry-resource (fifth entries)))))
    (check "wasm → :wasm"
           (eq :wasm (resource-provider (entry-resource (sixth entries)))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 4. DETERMINISTIC CANONICAL FORM + HASH STABILITY
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-canonical-determinism ()
  (format t "~%── canonical determinism ──~%")
  ;; Two semantically equivalent graphs written in different source order must
  ;; produce identical canonical strings.
  (let* ((src-a '(authority-graph
                  (principals
                   (principal :id "p"
                              :authority ((fs /data/** :write :read))))))
         (src-b '(authority-graph
                  (principals
                   (principal :id "p"
                              :authority ((fs /data/** :read :write))))))
         (ga (parse-authority-graph src-a))
         (gb (parse-authority-graph src-b))
         (ca (canonicalize-graph ga))
         (cb (canonicalize-graph gb)))
    (check "op order doesn't affect canonical string" (string= ca cb)))

  ;; Path sugar: /* vs /** should produce same canonical string after normalization.
  (let* ((sa '(authority-graph (principals (principal :id "p" :authority ((fs /data/* :read))))))
         (sb '(authority-graph (principals (principal :id "p" :authority ((fs /data/** :read))))))
         (ca (canonicalize-graph (parse-authority-graph sa)))
         (cb (canonicalize-graph (parse-authority-graph sb))))
    (check "path sugar /* = /** in canonical form" (string= ca cb)))

  ;; Node order in source does not affect canonical string (nodes sorted by id).
  (let* ((sa '(authority-graph
               (principals
                (principal :id "b" :authority ((fs /b/** :read)))
                (principal :id "a" :authority ((fs /a/** :read))))))
         (sb '(authority-graph
               (principals
                (principal :id "a" :authority ((fs /a/** :read)))
                (principal :id "b" :authority ((fs /b/** :read))))))
         (ca (canonicalize-graph (parse-authority-graph sa)))
         (cb (canonicalize-graph (parse-authority-graph sb))))
    (check "principal order doesn't affect canonical string" (string= ca cb))))

(defun test-canonical-distinguishes-distinct ()
  (format t "~%── canonical distinguishes distinct grants ──~%")
  ;; Different authority grants must produce different canonical strings.
  (let* ((ea (make-fs "/data/**"     :read))
         (eb (make-fs "/data/sub/**" :read))
         (ec (make-fs "/data/**"     :write)))
    (check "/data/** :read ≠ /data/sub/** :read"
           (not (string= (canonicalize-entry ea) (canonicalize-entry eb))))
    (check "/data/** :read ≠ /data/** :write"
           (not (string= (canonicalize-entry ea) (canonicalize-entry ec))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 5. ALGEBRA REGISTRY INTEGRITY
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-registry-completeness ()
  (format t "~%── algebra registry completeness ──~%")
  ;; Every known provider must have a registered predicate.
  (dolist (p +known-providers+)
    (check (format nil "~a has registered lattice predicate" p)
           (handler-case
               (progn
                 ;; Call lattice-subset-p with dummy dims; if no predicate registered it errors.
                 ;; We catch "unknown provider" errors; other errors mean predicate exists but
                 ;; rejected the (deliberately empty) dims — that's fine.
                 (lattice-subset-p p '(:path "/" :ops nil :conditions nil
                                       :host "" :port-min 0 :port-max 65535 :path-prefix "/"
                                       :ref :any :fd :any :url "/" :methods nil :module "*")
                                     '(:path "/**" :ops nil :conditions nil
                                       :host "*" :port-min 0 :port-max 65535 :path-prefix "/"
                                       :ref :any :fd :any :url "/**" :methods nil :module "*"))
                 t)
             (error (e)
               ;; "no lattice predicate" error = fail; anything else = pass (predicate exists)
               (let ((msg (format nil "~a" e)))
                 (not (search "no lattice predicate" msg))))))))

(defun test-unknown-provider-errors ()
  (format t "~%── unknown provider signals error ──~%")
  (check-error "unknown provider signals" error
    (lattice-subset-p :bogus-provider '() '())))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 6. END-TO-END PIPELINE
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-full-pipeline ()
  (format t "~%── full pipeline: parse → normalize → verify → canonical ──~%")
  (let* ((src '(authority-graph
                (roots
                 (root :kind :ambient-os :provider :linux :id "shim"
                       :authority ((fs /data/** :read :write)
                                   (net example.com :connect)
                                   (ipc-fd 3 :send :recv))))
                (principals
                 (principal :id "adapter"
                            :authority ((fs /data/session/** :read)
                                        (net example.com :connect)
                                        (ipc-fd 3 :send))))
                (delegate :from "shim" :to "adapter"
                          :authority ((fs /data/session/** :read)
                                      (net example.com :connect)
                                      (ipc-fd 3 :send)))))
         (raw-graph    (parse-authority-graph src))
         (normal-graph (normalize-graph raw-graph))
         (result       (verify-graph normal-graph))
         (canonical    (canonicalize-graph normal-graph)))
    (check "pipeline: parse succeeds" (not (null raw-graph)))
    (check "pipeline: normalize succeeds" (not (null normal-graph)))
    (check "pipeline: verify passes" (result-ok-p result))
    (check "pipeline: canonical is non-empty string"
           (and (stringp canonical) (> (length canonical) 0)))
    ;; Canonical string is stable across runs (deterministic).
    (check "pipeline: canonical is stable"
           (string= canonical (canonicalize-graph (normalize-graph (parse-authority-graph src)))))))

(defun test-three-hop-delegation ()
  (format t "~%── three-hop delegation chain ──~%")
  ;; shim (root) → adapter → mcp-tool
  ;; Each hop narrows the authority.  Verify the full chain.
  (let* ((src '(authority-graph
                (roots
                 (root :kind :ambient-os :provider :linux :id "shim"
                       :authority ((fs /workspace/** :read :write :execute))))
                (principals
                 (principal :id "adapter"
                            :authority ((fs /workspace/** :read :write)))
                 (principal :id "mcp-tool"
                            :authority ((fs /workspace/project/** :read))))
                (delegate :from "shim" :to "adapter"
                          :authority ((fs /workspace/** :read :write)))
                (delegate :from "adapter" :to "mcp-tool"
                          :authority ((fs /workspace/project/** :read)))))
         (g      (parse-authority-graph src))
         (result (verify-graph g)))
    (check "three-hop chain verifies" (result-ok-p result)))

  ;; Same chain but mcp-tool tries to escalate beyond adapter's grant.
  (let* ((src '(authority-graph
                (roots
                 (root :kind :ambient-os :provider :linux :id "shim"
                       :authority ((fs /workspace/** :read :write))))
                (principals
                 (principal :id "adapter"
                            :authority ((fs /workspace/** :read)))
                 (principal :id "mcp-tool"
                            :authority ((fs /workspace/** :write))))  ; :write not in adapter's grant
                (delegate :from "shim" :to "adapter"
                          :authority ((fs /workspace/** :read)))
                (delegate :from "adapter" :to "mcp-tool"
                          :authority ((fs /workspace/** :write)))))   ; escalation
         (g      (parse-authority-graph src))
         (result (verify-graph g)))
    (check "chain escalation at second hop detected" (not (result-ok-p result)))))

;;; ── Runner ───────────────────────────────────────────────────────────────────

(defun run-all-tests ()
  (setf *pass* 0 *fail* 0)
  (format t "~%═══ authority-dsl end-to-end tests ═══~%")
  (test-fs-lattice)
  (test-net-lattice)
  (test-net-port-lattice)
  (test-pid-lattice)
  (test-ipc-fd-lattice)
  (test-wasm-lattice)
  (test-condition-lattice)
  (test-cross-provider-rejection)
  (test-escalation-via-delegation)
  (test-valid-narrow-delegation)
  (test-parser-safety)
  (test-parser-sugar-expansion)
  (test-canonical-determinism)
  (test-canonical-distinguishes-distinct)
  (test-registry-completeness)
  (test-unknown-provider-errors)
  (test-full-pipeline)
  (test-three-hop-delegation)
  (format t "~%Results: ~a passed, ~a failed~%" *pass* *fail*)
  (zerop *fail*))

(run-all-tests)
