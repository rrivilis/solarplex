(defpackage #:authority-dsl/backends/linux
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir)
  (:export
   #:lower-to-linux
   #:emit-landlock-sexp
   ;; landlock-ruleset struct + accessors
   #:landlock-ruleset
   #:landlock-ruleset-p
   #:landlock-ruleset-fs-rules
   #:landlock-ruleset-net-rules
   #:landlock-ruleset-pid-rules
   ;; landlock-fs-rule struct + accessors
   #:landlock-fs-rule
   #:landlock-fs-rule-p
   #:landlock-fs-rule-path
   #:landlock-fs-rule-flags
   ;; landlock-net-rule struct + accessors
   #:landlock-net-rule
   #:landlock-net-rule-p
   #:landlock-net-rule-port
   #:landlock-net-rule-flags
   ;; landlock-pid-rule struct + accessors
   #:landlock-pid-rule
   #:landlock-pid-rule-p
   #:landlock-pid-rule-pidfd-ref))

(in-package #:authority-dsl/backends/linux)

;;; ── Op → Landlock flag mappings ──────────────────────────────────────────────
;;;
;;; Landlock groups fs access rights into distinct flags; we map our abstract
;;; op keywords to the nearest Landlock constant.  Missing ops default to none.

(defparameter *fs-op->landlock*
  '(:read        "LANDLOCK_ACCESS_FS_READ_FILE"
    :read-dir    "LANDLOCK_ACCESS_FS_READ_DIR"
    :write       "LANDLOCK_ACCESS_FS_WRITE_FILE"
    :execute     "LANDLOCK_ACCESS_FS_EXECUTE"
    :create      "LANDLOCK_ACCESS_FS_MAKE_REG"
    :create-dir  "LANDLOCK_ACCESS_FS_MAKE_DIR"
    :delete      "LANDLOCK_ACCESS_FS_REMOVE_FILE"
    :delete-dir  "LANDLOCK_ACCESS_FS_REMOVE_DIR"
    :truncate    "LANDLOCK_ACCESS_FS_TRUNCATE"))

(defparameter *net-op->landlock*
  '(:connect  "LANDLOCK_ACCESS_NET_CONNECT_TCP"
    :bind     "LANDLOCK_ACCESS_NET_BIND_TCP"))

;;; ── Output IR ────────────────────────────────────────────────────────────────
;;; The lowering returns a LANDLOCK-RULESET struct, not raw C.
;;; A codegen step (not included here) can emit C or a Rust landlock crate call.

(defstruct landlock-fs-rule
  path           ; string — the path passed to landlock_add_rule
  flags)         ; list of strings — Landlock flag names

(defstruct landlock-net-rule
  port           ; integer or :any
  flags)         ; list of strings

(defstruct landlock-pid-rule
  pidfd-ref)     ; fd integer or :any

(defstruct landlock-ruleset
  fs-rules        ; list of landlock-fs-rule
  net-rules       ; list of landlock-net-rule
  pid-rules)      ; list of landlock-pid-rule

;;; ── Lowering entry point ──────────────────────────────────────────────────────

(defun lower-to-linux (node)
  "Lower a CAP-NODE's authority entries to a LANDLOCK-RULESET.
   Non-Linux providers (ipc-fd, http-ucan, wasm) are silently skipped —
   they are enforced at the fd/UCAN/sandbox layer, not Landlock."
  (let (fs-rules net-rules pid-rules)
    (dolist (entry (node-authority node))
      (let ((resource (entry-resource entry))
            (ops      (entry-ops entry)))
        (etypecase resource
          (fs-resource
           (push (lower-fs resource ops) fs-rules))
          (net-resource
           (push (lower-net resource ops) net-rules))
          (pid-resource
           (push (lower-pid resource) pid-rules))
          ;; ipc-fd: enforced by fd inheritance; no Landlock rule needed
          (ipc-fd-resource nil)
          ;; http-ucan: enforced by UCAN caveat; no Landlock rule needed
          (http-resource nil))))
    (make-landlock-ruleset
     :fs-rules  (nreverse fs-rules)
     :net-rules (nreverse net-rules)
     :pid-rules (nreverse pid-rules))))

(defun lower-fs (resource ops)
  (let* ((pattern (path-glob-pattern (fs-resource-path resource)))
         ;; Strip trailing /** — Landlock takes the directory path, not a glob.
         (path    (if (and (> (length pattern) 3)
                           (string= pattern "/**" :start1 (- (length pattern) 3)))
                      (subseq pattern 0 (- (length pattern) 3))
                      pattern))
         (flags   (mapcan (lambda (op)
                            (let ((f (getf *fs-op->landlock* op)))
                              (when f (list f))))
                          (ops ops))))
    (make-landlock-fs-rule :path path :flags flags)))

(defun lower-net (resource ops)
  ;; Landlock net rules are port-based; we don't parse ports from the IR host
  ;; string here — emit :any so the caller can bind a specific port if needed.
  (declare (ignore resource))
  (let ((flags (mapcan (lambda (op)
                         (let ((f (getf *net-op->landlock* op)))
                           (when f (list f))))
                       (ops ops))))
    (make-landlock-net-rule :port :any :flags flags)))

(defun lower-pid (resource)
  (make-landlock-pid-rule :pidfd-ref (pid-resource-ref resource)))

;;; ── S-expression emission ────────────────────────────────────────────────────
;;; Produce a canonical s-expression representation of a LANDLOCK-RULESET
;;; suitable for serialisation, signing, or REPL inspection.

(defun emit-landlock-sexp (ruleset)
  "Return an s-expression (list) representing RULESET."
  `(landlock-ruleset
    (fs-rules
     ,@(mapcar (lambda (r)
                 `(rule :path ,(landlock-fs-rule-path r)
                        :flags ,(landlock-fs-rule-flags r)))
               (landlock-ruleset-fs-rules ruleset)))
    (net-rules
     ,@(mapcar (lambda (r)
                 `(rule :port ,(landlock-net-rule-port r)
                        :flags ,(landlock-net-rule-flags r)))
               (landlock-ruleset-net-rules ruleset)))
    (pid-rules
     ,@(mapcar (lambda (r)
                 `(rule :pidfd ,(landlock-pid-rule-pidfd-ref r)))
               (landlock-ruleset-pid-rules ruleset)))))

;;; ── AUTHORITY-SUBSET-P extension for linux backend (no new methods needed) ──
;;; The fs/net/pid resource-subset-p methods are already in ir.lisp.
;;; The backend only needs to add lowering; no new defmethods required here.
