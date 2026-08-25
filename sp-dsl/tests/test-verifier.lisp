(defpackage #:authority-dsl/tests/verifier
  (:use #:cl
        #:authority-dsl/algebra
        #:authority-dsl/ir
        #:authority-dsl/parser
        #:authority-dsl/normalizer
        #:authority-dsl/verifier
        #:authority-dsl/backends/linux))

(in-package #:authority-dsl/tests/verifier)

;;; Minimal test runner — no external dependency.
(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (label form)
  `(if ,form
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a~%" ,label))))

(defmacro check-errors (label form)
  "Expect FORM to signal an error."
  `(if (handler-case (progn ,form nil) (error () t))
       (progn (incf *pass*) (format t "  PASS  ~a (error signalled)~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a (no error)~%" ,label))))

;;; ── Algebra tests ─────────────────────────────────────────────────────────────

(defun test-op-set ()
  (format t "~%── op-set ──~%")
  (let ((r   (op-set :read))
        (rw  (op-set :read :write))
        (nil-set (op-set)))
    (check ":read ⊆ :read/:write"          (op-set-subset-p r rw))
    (check ":read/:write ⊄ :read"          (not (op-set-subset-p rw r)))
    (check "∅ ⊆ :read"                    (op-set-subset-p nil-set r))
    (check ":read ⊄ ∅"                    (not (op-set-subset-p r nil-set)))))

(defun test-path-glob ()
  (format t "~%── path-glob ──~%")
  (let ((data    (path-glob "/data/**"))
        (data-sub (path-glob "/data/foo/**"))
        (tmp     (path-glob "/tmp/**"))
        (exact   (path-glob "/data")))
    (check "/data/foo/** ⊆ /data/**"      (path-glob-subset-p data-sub data))
    (check "/data/** ⊄ /data/foo/**"      (not (path-glob-subset-p data data-sub)))
    (check "/tmp/** ⊄ /data/**"           (not (path-glob-subset-p tmp data)))
    (check "/data ⊆ /data/**"             (path-glob-subset-p exact data))
    (check "/data/** = /data/**"           (path-glob-subset-p data data))))

(defun test-conditions ()
  (format t "~%── conditions ──~%")
  (let ((loose  (condition-set :ttl 3600 :quorum 1))
        (tight  (condition-set :ttl 1800 :quorum 2))
        (relax  (condition-set :ttl 7200 :quorum 1)))
    (check "shorter ttl + higher quorum is tighter"
           (condition-set-tighter-p tight loose))
    (check "relaxed ttl fails"
           (not (condition-set-tighter-p relax loose)))))

;;; ── IR + verifier tests ───────────────────────────────────────────────────────

(defun make-entry (resource &rest ops)
  (make-instance 'authority-entry
                 :resource resource
                 :ops (apply #'op-set ops)))

(defun test-authority-subset ()
  (format t "~%── authority-subset-p ──~%")
  (let* ((parent-fs (make-instance 'fs-resource :path (path-glob "/data/**")))
         (child-fs  (make-instance 'fs-resource :path (path-glob "/data/foo/**")))
         (other-fs  (make-instance 'fs-resource :path (path-glob "/tmp/**")))
         (pe (make-entry parent-fs :read :write))
         (ce (make-entry child-fs  :read))
         (oe (make-entry other-fs  :read)))
    (check "child /data/foo/** :read ⊆ parent /data/** :read/:write"
           (authority-subset-p ce pe))
    (check "/tmp/** :read ⊄ /data/** :read/:write"
           (not (authority-subset-p oe pe)))))

;;; ── Verifier: valid delegation ────────────────────────────────────────────────

(defun test-valid-delegation ()
  (format t "~%── verify-graph valid ──~%")
  (let* ((graph (make-authority-graph))
         (shim-res (make-instance 'fs-resource :path (path-glob "/data/**")))
         (adap-res (make-instance 'fs-resource :path (path-glob "/data/session/**")))
         (shim-entry (make-entry shim-res :read :write))
         (adap-entry (make-entry adap-res :read))
         (shim-prin (make-instance 'principal :id "shim"))
         (adap-prin (make-instance 'principal :id "adapter"))
         (root (make-instance 'root-authority :kind :ambient-os :provider :linux))
         (shim-node (make-instance 'cap-node :principal shim-prin
                                             :authority (list shim-entry)
                                             :root root))
         (adap-node (make-instance 'cap-node :principal adap-prin
                                             :authority (list adap-entry)
                                             :root nil))
         (edge (make-instance 'delegation :grantor "shim" :grantee "adapter"
                                          :authority (list adap-entry))))
    (graph-add-node graph shim-node)
    (graph-add-node graph adap-node)
    (graph-add-delegation graph edge)
    (let ((result (verify-graph graph)))
      (check "valid delegation verifies ok" (result-ok-p result)))))

;;; ── Verifier: escalation detected ───────────────────────────────────────────

(defun test-escalation-detected ()
  (format t "~%── verify-graph escalation ──~%")
  (let* ((graph (make-authority-graph))
         ;; shim only has :read on /data/foo
         (shim-res  (make-instance 'fs-resource :path (path-glob "/data/foo/**")))
         ;; adapter tries to claim :write on broader /data/**
         (adap-res  (make-instance 'fs-resource :path (path-glob "/data/**")))
         (shim-entry (make-entry shim-res :read))
         (adap-entry (make-entry adap-res :read :write))
         (shim-prin (make-instance 'principal :id "shim"))
         (adap-prin (make-instance 'principal :id "adapter"))
         (root (make-instance 'root-authority :kind :ambient-os :provider :linux))
         (shim-node (make-instance 'cap-node :principal shim-prin
                                             :authority (list shim-entry)
                                             :root root))
         (adap-node (make-instance 'cap-node :principal adap-prin
                                             :authority (list adap-entry)
                                             :root nil))
         (edge (make-instance 'delegation :grantor "shim" :grantee "adapter"
                                          :authority (list adap-entry))))
    (graph-add-node graph shim-node)
    (graph-add-node graph adap-node)
    (graph-add-delegation graph edge)
    (let ((result (verify-graph graph)))
      (check "authority escalation is detected" (not (result-ok-p result)))
      (check "error message present" (consp (result-errors result))))))

;;; ── Parser round-trip ─────────────────────────────────────────────────────────

(defun test-parser-roundtrip ()
  (format t "~%── parser round-trip ──~%")
  (let* ((src '(authority-graph
                (roots
                 (root :kind :ambient-os :provider :linux :id "shim"
                       :authority ((fs /data/** :read :write))))
                (principals
                 (principal :id "adapter"
                            :authority ((fs /data/session/** :read))))
                (delegate :from "shim" :to "adapter"
                          :authority ((fs /data/session/** :read)))))
         (graph (parse-authority-graph src))
         (result (verify-graph graph)))
    (check "parsed graph has shim node"
           (not (null (graph-node-for graph "shim"))))
    (check "parsed graph has adapter node"
           (not (null (graph-node-for graph "adapter"))))
    (check "parsed graph verifies ok"
           (result-ok-p result))))

;;; ── Linux backend lowering ────────────────────────────────────────────────────

(defun test-linux-lowering ()
  (format t "~%── linux backend ──~%")
  (let* ((graph (parse-authority-graph
                 '(authority-graph
                   (roots
                    (root :kind :ambient-os :provider :linux :id "shim"
                          :authority ((fs /data/** :read :write)
                                      (net example.com :connect)))))))
         (node     (graph-node-for graph "shim"))
         (ruleset  (lower-to-linux node))
         (sexp     (emit-landlock-sexp ruleset)))
    (check "fs rule generated"
           (= 1 (length (landlock-ruleset-fs-rules ruleset))))
    (check "net rule generated"
           (= 1 (length (landlock-ruleset-net-rules ruleset))))
    (check "fs rule path is /data"
           (string= "/data" (landlock-fs-rule-path
                             (first (landlock-ruleset-fs-rules ruleset)))))
    (check "sexp starts with landlock-ruleset"
           (eq 'landlock-ruleset (car sexp)))))

;;; ── Parser error handling ─────────────────────────────────────────────────────

(defun test-parser-errors ()
  (format t "~%── parser errors ──~%")
  (check-errors "bad top form"
    (parse-authority-graph '(not-a-graph)))
  (check-errors "missing :id in root"
    (parse-authority-graph '(authority-graph
                              (roots (root :kind :ambient-os :provider :linux))))))

;;; ── Normalizer tests ─────────────────────────────────────────────────────────

(defun test-path-normalization ()
  (format t "~%── path normalization ──~%")
  (check "/data/* → /data/**"
         (string= "/data/**" (normalize-path-pattern "/data/*")))
  (check "/data/ → /data"
         (string= "/data" (normalize-path-pattern "/data/")))
  (check "/ → /**"
         (string= "/**" (normalize-path-pattern "/")))
  (check "/data/** unchanged"
         (string= "/data/**" (normalize-path-pattern "/data/**")))
  (check "/data (exact) unchanged"
         (string= "/data" (normalize-path-pattern "/data"))))

(defun test-ops-normalization ()
  (format t "~%── ops normalization ──~%")
  (let ((shuffled (make-instance 'op-set :ops '(:write :read :write :execute))))
    (let ((normed (normalize-ops shuffled)))
      (check "dedup + sort: execute read write"
             (equal '(:execute :read :write) (ops normed))))))

(defun test-entry-normalization ()
  (format t "~%── entry normalization ──~%")
  (let* ((raw-res (make-instance 'fs-resource :path (path-glob "/data/*")))
         (raw-ops (make-instance 'op-set :ops '(:write :read)))
         (entry   (make-instance 'authority-entry :resource raw-res :ops raw-ops))
         (normed  (normalize-entry entry)))
    (check "path sugar expanded"
           (string= "/data/**" (path-glob-pattern (fs-resource-path (entry-resource normed)))))
    (check "ops sorted"
           (equal '(:read :write) (ops (entry-ops normed))))))

(defun test-canonical-stability ()
  (format t "~%── canonical stability ──~%")
  ;; Two entries that are semantically identical but written differently should
  ;; produce the same canonical string.
  (let* ((res-a (make-instance 'fs-resource :path (path-glob "/data/*")))
         (res-b (make-instance 'fs-resource :path (path-glob "/data/**")))
         (ea (make-instance 'authority-entry :resource res-a
                            :ops (make-instance 'op-set :ops '(:write :read))))
         (eb (make-instance 'authority-entry :resource res-b
                            :ops (make-instance 'op-set :ops '(:read :write)))))
    (check "canonical strings match after normalization"
           (string= (canonicalize-entry ea) (canonicalize-entry eb)))))

(defun test-host-normalization ()
  (format t "~%── net host normalization ──~%")
  (let* ((res (make-instance 'net-resource :host "Example.COM" :path-prefix "/"))
         (normed (normalize-resource res)))
    (check "host lowercased"
           (string= "example.com" (net-resource-host normed)))))

(defun test-merge-same-resource ()
  (format t "~%── merge same-resource entries ──~%")
  (let* ((res   (make-instance 'fs-resource :path (path-glob "/data/**")))
         (entry-r  (make-instance 'authority-entry :resource res
                                  :ops (op-set :read)))
         (entry-w  (make-instance 'authority-entry :resource res
                                  :ops (op-set :write)))
         (merged (normalize-entries (list entry-r entry-w))))
    (check "two entries on same resource merged to one"
           (= 1 (length merged)))
    (check "merged entry has both ops"
           (let ((merged-ops (ops (entry-ops (first merged)))))
             (and (member :read merged-ops) (member :write merged-ops))))))

;;; ── Runner ───────────────────────────────────────────────────────────────────

(defun run-all-tests ()
  (setf *pass* 0 *fail* 0)
  (format t "~%═══ authority-dsl verifier tests ═══~%")
  (test-op-set)
  (test-path-glob)
  (test-conditions)
  (test-authority-subset)
  (test-valid-delegation)
  (test-escalation-detected)
  (test-parser-roundtrip)
  (test-linux-lowering)
  (test-parser-errors)
  (test-path-normalization)
  (test-ops-normalization)
  (test-entry-normalization)
  (test-canonical-stability)
  (test-host-normalization)
  (test-merge-same-resource)
  (format t "~%Results: ~a passed, ~a failed~%" *pass* *fail*)
  (zerop *fail*))

(run-all-tests)
