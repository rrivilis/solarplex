(defpackage #:authority-dsl/algebra
  (:use #:cl)
  (:export
   ;; Op sets
   #:op-set #:ops #:op-set-p
   #:op-set-subset-p #:op-set-union #:op-set-intersection #:empty-op-set-p
   ;; Path globs
   #:path-glob #:path-glob-pattern #:path-glob-p #:path-glob-subset-p
   ;; Port ranges
   #:port-range #:port-range-min #:port-range-max #:port-range-p
   #:port-range-any #:port-range-subset-p
   ;; Conditions
   #:condition-set #:condition-set-conditions #:condition-set-p
   #:condition-set-tighter-p #:%conditions-satisfied-p
   ;; Provider lattice registry — the single authoritative verification path
   #:register-provider-lattice
   #:lattice-subset-p
   #:+known-providers+))

(in-package #:authority-dsl/algebra)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; AUTHORITY LATTICE ALGEBRA
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; This file defines three independent lattices used across all providers,
;;; plus a registry of per-provider subset predicates.  The registry is the
;;; ONLY path through which authority-subset-p (ir.lisp) should dispatch.
;;;
;;; Invariant: ∀ provider P, delegate(child, parent) is valid iff
;;;   lattice-subset-p P child-dims parent-dims ≡ ⊤
;;;
;;; "dims" is a plist whose shape is provider-specific (see PROVIDER CONTRACTS
;;; below).  All predicates are pure functions of their arguments — no side
;;; effects, no backend knowledge.

;;; ── Op sets (power-set lattice) ──────────────────────────────────────────────
;;; Lattice order: A ⊑ B  iff  ops(A) ⊆ ops(B)
;;; Top: {all possible ops}    Bottom: ∅

(defclass op-set ()
  ((ops :initarg :ops :reader ops :initform nil)))

(defun op-set (&rest kws)
  "Construct an op-set.  Duplicate keywords are removed."
  (make-instance 'op-set :ops (remove-duplicates kws)))

(defun op-set-subset-p (child parent)
  "A ⊑ B in the power-set lattice: every op in CHILD is in PARENT."
  (every (lambda (op) (member op (ops parent))) (ops child)))

(defun op-set-union (a b)
  (make-instance 'op-set :ops (remove-duplicates (append (ops a) (ops b)))))

(defun op-set-intersection (a b)
  (make-instance 'op-set :ops (intersection (ops a) (ops b))))

(defun empty-op-set-p (s) (null (ops s)))

;;; ── Path globs (prefix-containment lattice) ──────────────────────────────────
;;; Lattice order: child ⊑ parent  iff  every path child matches is also
;;;   matched by parent.
;;;
;;; Supported forms:
;;;   /data/**          — recursive glob: matches /data and everything under it
;;;   /data/file.txt    — exact path
;;;
;;; Formal subset rule:
;;;   glob(cp) ⊑ glob(pp)  iff
;;;     cp = pp                          (equal patterns)
;;;   ∨ pp = prefix "/**" ∧ cp has prefix as path prefix
;;;
;;; Note: child having a recursive glob does NOT ⊑ parent with a narrower
;;; exact path — /data/** ⊄ /data/file.txt.

(defclass path-glob ()
  ((pattern :initarg :pattern :reader path-glob-pattern :type string)))

(defun path-glob (pattern)
  (make-instance 'path-glob :pattern pattern))

(defun path-glob-subset-p (child parent)
  (let ((cp (path-glob-pattern child))
        (pp (path-glob-pattern parent)))
    (cond
      ;; Equal patterns.
      ((string= cp pp) t)
      ;; Parent is "/**" (root wildcard) — covers everything.
      ((string= pp "/**") t)
      ;; Parent is a recursive glob: child must be a subpath of its prefix.
      ((and (>= (length pp) 3)
            (string= pp "/**" :start1 (- (length pp) 3)))
       (let ((prefix (subseq pp 0 (- (length pp) 3))))
         (or (string= cp prefix)
             (and (> (length cp) (length prefix))
                  (string= cp prefix :end1 (length prefix))
                  (char= (char cp (length prefix)) #\/)))))
      ;; Child is a recursive glob — cannot be ⊆ an exact parent path.
      ((and (>= (length cp) 3)
            (string= cp "/**" :start1 (- (length cp) 3)))
       nil)
      ;; Both exact: must be equal (already handled above).
      (t nil))))

;;; ── Port ranges (interval lattice) ───────────────────────────────────────────
;;; Lattice order: [a,b] ⊑ [c,d]  iff  c ≤ a ∧ b ≤ d  (interval containment).
;;; Top: [0, 65535]   Bottom: empty interval.

(defclass port-range ()
  ((min-port :initarg :min-port :reader port-range-min :initform 0    :type fixnum)
   (max-port :initarg :max-port :reader port-range-max :initform 65535 :type fixnum)))

(defun port-range (min-port max-port)
  (assert (<= min-port max-port) () "port-range min ~a > max ~a" min-port max-port)
  (make-instance 'port-range :min-port min-port :max-port max-port))

(defun port-range-any ()
  "The top element: covers all ports."
  (make-instance 'port-range :min-port 0 :max-port 65535))

(defun port-range-subset-p (child parent)
  "[child.min, child.max] ⊆ [parent.min, parent.max]"
  (and (>= (port-range-min child) (port-range-min parent))
       (<= (port-range-max child) (port-range-max parent))))

;;; ── Conditions (contravariant tightening lattice) ─────────────────────────────
;;; Delegation is monotone: a child can only tighten conditions, never relax.
;;; "Tighter" differs per key:
;;;   :ttl        — shorter is tighter (child ≤ parent)
;;;   :quorum     — higher is tighter (child ≥ parent)
;;;   :single-use — boolean; if parent requires it, child must too
;;;   :audit      — boolean; if parent requires it, child must too
;;;
;;; An absent parent condition places no constraint on the child for that key.
;;; An absent child condition when the parent has one is a VIOLATION.

(defclass condition-set ()
  ((conditions :initarg :conditions :reader condition-set-conditions :initform nil)))

(defun condition-set (&rest plist)
  (make-instance 'condition-set :conditions plist))

(defun %cval (cset key)
  (getf (condition-set-conditions cset) key))

(defun %quorum-tighter-p (child-q parent-q)
  "True iff CHILD-Q is at least as restrictive as PARENT-Q.
   Quorum may be:
     integer  — threshold; child ≥ parent
     list     — required party set; child ⊇ parent (conjunction)
     symbol   — treated as a singleton list"
  (flet ((as-set (q)
           (cond ((null q)    nil)
                 ((integerp q) q)          ; keep as integer
                 ((symbolp q)  (list q))
                 ((listp q)    q))))
    (let ((cp (as-set child-q))
          (pp (as-set parent-q)))
      (cond
        ;; Both numeric thresholds.
        ((and (integerp cp) (integerp pp)) (>= cp pp))
        ;; Both sets: child must require every party parent requires.
        ((and (listp cp) (listp pp))
         (every (lambda (party) (member party cp)) pp))
        ;; Mixed: symbolic quorum ⊒ numeric threshold if set size ≥ threshold.
        ((and (listp cp) (integerp pp)) (>= (length cp) pp))
        (t nil)))))

(defun condition-set-tighter-p (child parent)
  "True iff CHILD satisfies or exceeds every restriction in PARENT.
   Condition keys and their monotonicity:
     :ttl        — duration in seconds; shorter is tighter (child ≤ parent)
     :expires-at — unix timestamp; sooner is tighter (child ≤ parent)
     :quorum     — integer threshold or party set; higher/larger is tighter
     :epoch      — monotonic counter; child ≥ parent (newer epoch is acceptable)
     :single-use — boolean; if parent requires it, child must too
     :audit      — boolean; if parent requires it, child must too"
  (loop for (key val) on (condition-set-conditions parent) by #'cddr
        always (let ((cv (%cval child key)))
                 (ecase key
                   (:ttl        (and cv (<= cv val)))
                   (:expires-at (and cv (<= cv val)))
                   (:quorum     (and cv (%quorum-tighter-p cv val)))
                   (:epoch      (and cv (>= cv val)))
                   (:single-use (or (not val) cv))
                   (:audit      (or (not val) cv))))))

;;; Helper used by the lattice predicates below.
(defun %conditions-satisfied-p (child-cset parent-cset)
  "True iff CHILD-CSET satisfies the constraints in PARENT-CSET.
   NIL parent = no constraints (always satisfied).
   NIL child when parent has constraints = violation."
  (cond ((null parent-cset) t)
        ((null child-cset)  nil)
        (t (condition-set-tighter-p child-cset parent-cset))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; PROVIDER LATTICE REGISTRY
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Each provider registers a pure predicate:
;;;   (child-dims parent-dims) → boolean
;;;
;;; DIMS CONTRACTS (provider → required plist keys):
;;;
;;;   :linux-fs   :path (string glob)
;;;               :ops  (list of keywords)
;;;               :conditions (condition-set or nil)
;;;
;;;   :linux-net  :host (string, "*" = wildcard)
;;;               :port-min (fixnum 0–65535)
;;;               :port-max (fixnum 0–65535)
;;;               :path-prefix (string)
;;;               :ops (list of keywords)
;;;               :conditions (condition-set or nil)
;;;
;;;   :linux-pid  :ref (:any | integer pidfd)
;;;               :ops (list of keywords)
;;;               :conditions (condition-set or nil)
;;;
;;;   :ipc-fd     :fd (:any | integer fd number)
;;;               :ops (list of keywords)
;;;               :conditions (condition-set or nil)
;;;
;;;   :http-ucan  :url (string glob)
;;;               :methods (list of keywords, e.g. :get :post)
;;;               :conditions (condition-set or nil)
;;;
;;;   :wasm       :module (string, module identifier or "*")
;;;               :ops (list of keywords)
;;;               :conditions (condition-set or nil)

(defvar *provider-lattices* (make-hash-table)
  "Maps provider keyword → (child-dims parent-dims) → boolean predicate.
  Populated at load time.  Backends must not add entries here.")

(defun register-provider-lattice (provider-kw predicate)
  "Register PREDICATE as the canonical subset checker for PROVIDER-KW.
  Must only be called from algebra setup (this file).  Any call from a
  backend package is a design violation — backends lower IR to native
  representations; they do not redefine what subset means."
  (setf (gethash provider-kw *provider-lattices*) predicate))

(defun lattice-subset-p (provider-kw child-dims parent-dims)
  "Dispatch subset check to the algebra-registered predicate for PROVIDER-KW.
  Signals an error if no predicate is registered (unknown provider)."
  (let ((pred (gethash provider-kw *provider-lattices*)))
    (unless pred
      (error "no lattice predicate registered for provider ~s — ~
              add a register-provider-lattice call in algebra.lisp" provider-kw))
    (funcall pred child-dims parent-dims)))

;;; ── Helper: extract an op-set from a dims plist ──────────────────────────────

(defun %dims-op-set (dims key)
  (make-instance 'op-set :ops (getf dims key nil)))

;;; ── :linux-fs predicate ───────────────────────────────────────────────────────
;;; Authority: (path-glob × op-set × conditions)
;;; Subset:    child.path ⊑ parent.path
;;;          ∧ child.ops ⊑ parent.ops
;;;          ∧ child.conditions ≽ parent.conditions (tighter)

(defun %linux-fs-subset-p (child parent)
  (and (path-glob-subset-p (path-glob (getf child :path))
                           (path-glob (getf parent :path)))
       (op-set-subset-p (%dims-op-set child :ops)
                        (%dims-op-set parent :ops))
       (%conditions-satisfied-p (getf child :conditions)
                                (getf parent :conditions))))

;;; ── :linux-net predicate ──────────────────────────────────────────────────────
;;; Authority: (host × port-range × path-prefix × op-set × conditions)
;;; Subset:    child.host ∈ {parent.host, "*"}
;;;          ∧ child.ports ⊑ parent.ports
;;;          ∧ child.path-prefix ⊑ parent.path-prefix (prefix containment)
;;;          ∧ child.ops ⊑ parent.ops
;;;          ∧ child.conditions ≽ parent.conditions

(defun %linux-net-subset-p (child parent)
  (let ((ph (getf parent :host))
        (ch (getf child  :host))
        (pp (getf parent :path-prefix "/"))
        (cp (getf child  :path-prefix "/")))
    (and ;; host: parent wildcard covers all; otherwise must match
         (or (string= ph "*") (string= ch ph))
         ;; port range containment
         (port-range-subset-p
          (port-range (getf child  :port-min 0) (getf child  :port-max 65535))
          (port-range (getf parent :port-min 0) (getf parent :port-max 65535)))
         ;; path prefix: child prefix must start with parent prefix
         (or (string= pp "/")
             (and (<= (length pp) (length cp))
                  (string= cp pp :end1 (length pp))))
         (op-set-subset-p (%dims-op-set child :ops)
                          (%dims-op-set parent :ops))
         (%conditions-satisfied-p (getf child :conditions)
                                  (getf parent :conditions)))))

;;; ── :linux-pid predicate ──────────────────────────────────────────────────────
;;; Authority: (pid-ref × op-set × conditions)
;;; :any in parent = capability covers any process (top element of pid lattice)
;;; An exact pidfd ref is a specific handle; child must match or parent must be :any.

(defun %linux-pid-subset-p (child parent)
  (and (or (eq (getf parent :ref) :any)
           (equal (getf child :ref) (getf parent :ref)))
       (op-set-subset-p (%dims-op-set child :ops)
                        (%dims-op-set parent :ops))
       (%conditions-satisfied-p (getf child :conditions)
                                (getf parent :conditions))))

;;; ── :ipc-fd predicate ────────────────────────────────────────────────────────
;;; Authority: (fd × op-set × conditions)
;;; :any in parent = authority over any inherited socket (top element).
;;; An exact fd number is a specific socket; child must match or parent is :any.

(defun %ipc-fd-subset-p (child parent)
  (and (or (eq (getf parent :fd) :any)
           (equal (getf child :fd) (getf parent :fd)))
       (op-set-subset-p (%dims-op-set child :ops)
                        (%dims-op-set parent :ops))
       (%conditions-satisfied-p (getf child :conditions)
                                (getf parent :conditions))))

;;; ── :http-ucan predicate ─────────────────────────────────────────────────────
;;; Authority: (url-glob × method-set × conditions)
;;; Methods use the same power-set lattice as op-set (GET POST PUT DELETE etc.).
;;; Conditions carry UCAN-level caveats (:ttl = exp claim, :single-use = nonce).

(defun %http-ucan-subset-p (child parent)
  (and (path-glob-subset-p (path-glob (getf child :url))
                           (path-glob (getf parent :url)))
       (op-set-subset-p (%dims-op-set child :methods)
                        (%dims-op-set parent :methods))
       (%conditions-satisfied-p (getf child :conditions)
                                (getf parent :conditions))))

;;; ── :wasm predicate ──────────────────────────────────────────────────────────
;;; Authority: (module-id × op-set × conditions)
;;; module-id: exact string or "*" (any module, top element).
;;; Ops: :instantiate :execute :import-func :export-memory :table-access

(defun %wasm-subset-p (child parent)
  (let ((pm (getf parent :module))
        (cm (getf child  :module)))
    (and (or (string= pm "*") (string= cm pm))
         (op-set-subset-p (%dims-op-set child :ops)
                          (%dims-op-set parent :ops))
         (%conditions-satisfied-p (getf child :conditions)
                                  (getf parent :conditions)))))

;;; ── Registration ─────────────────────────────────────────────────────────────

(register-provider-lattice :linux-fs  #'%linux-fs-subset-p)
(register-provider-lattice :linux-net #'%linux-net-subset-p)
(register-provider-lattice :linux-pid #'%linux-pid-subset-p)
(register-provider-lattice :ipc-fd    #'%ipc-fd-subset-p)
(register-provider-lattice :http-ucan #'%http-ucan-subset-p)
(register-provider-lattice :wasm      #'%wasm-subset-p)

;;; ── Known providers ──────────────────────────────────────────────────────────

(defparameter +known-providers+
  '(:linux-fs :linux-net :linux-pid :ipc-fd :http-ucan :wasm))
