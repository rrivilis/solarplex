(defpackage #:authority-dsl/normalizer
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir)
  (:export
   ;; Normalization
   #:normalize-graph
   #:normalize-node
   #:normalize-entry
   #:normalize-entries
   #:normalize-resource
   #:normalize-ops
   #:normalize-conditions
   ;; Canonical form (deterministic string)
   #:canonicalize-entry
   #:canonicalize-node
   #:canonicalize-graph
   ;; Hashing (pluggable)
   #:hash-entry
   #:hash-node
   #:hash-graph
   #:*hash-function*
   ;; Sugar expansion
   #:expand-provider-alias
   #:normalize-path-pattern
   ;; Conditions
   #:normalization-warning))

(in-package #:authority-dsl/normalizer)

;;; ── Hash function hook ───────────────────────────────────────────────────────
;;; The normalizer produces a deterministic string; callers supply the hash
;;; function.  This keeps the library dep-free while supporting real crypto.
;;;
;;; Example wiring with ironclad + babel:
;;;   (setf authority-dsl/normalizer:*hash-function*
;;;         (lambda (s)
;;;           (ironclad:byte-array-to-hex-string
;;;            (ironclad:digest-sequence
;;;             :sha256 (babel:string-to-octets s :encoding :utf-8)))))

(defparameter *hash-function* nil
  "NIL or a function (string → hex-string).  If NIL, hash-* functions return
  the raw canonical string instead of a hash (useful for testing).")

(define-condition normalization-warning (warning)
  ((message :initarg :message :reader normalization-warning-message)
   (form    :initarg :form    :reader normalization-warning-form :initform nil))
  (:report (lambda (c s)
             (format s "authority-dsl normalizer warning: ~a~@[ in ~s~]"
                     (normalization-warning-message c)
                     (normalization-warning-form c)))))

;;; ── Provider alias expansion ─────────────────────────────────────────────────
;;; The parser accepts short aliases; normalizer collapses them to the
;;; canonical keyword form used throughout the IR.

(defparameter *provider-aliases*
  '((fs       . :linux-fs)
    (:fs      . :linux-fs)
    (linux-fs . :linux-fs)
    (net      . :linux-net)
    (:net     . :linux-net)
    (linux-net . :linux-net)
    (pid      . :linux-pid)
    (:pid     . :linux-pid)
    (linux-pid . :linux-pid)
    (ipc      . :ipc-fd)
    (:ipc     . :ipc-fd)
    (ipc-fd   . :ipc-fd)
    (http     . :http-ucan)
    (:http    . :http-ucan)
    (ucan     . :http-ucan)
    (:ucan    . :http-ucan)
    (wasm     . :wasm)
    (:wasm    . :wasm)))

(defun expand-provider-alias (kw)
  "Resolve any provider alias to the canonical keyword.  Signals if unknown."
  (or (cdr (assoc kw *provider-aliases* :test #'string=))
      (progn
        (warn 'normalization-warning :message (format nil "unknown provider alias ~s" kw) :form kw)
        kw)))

;;; ── Path normalization ────────────────────────────────────────────────────────
;;; Rules:
;;;   /data/       → /data          (strip trailing slash unless root)
;;;   /data/*      → /data/**       (single-star glob → recursive)
;;;   /data        → /data          (exact path, no glob — left as-is)
;;;   /data/**     → /data/**       (already canonical)
;;;   /            → /**            (root wildcard)
;;;   /**          → /**            (root wildcard canonical)

(defun normalize-path-pattern (pattern)
  "Return the canonical path-glob pattern string for PATTERN."
  (let* ((s (string pattern))
         ;; Strip trailing slash unless the whole string is "/"
         (s (if (and (> (length s) 1) (char= (char s (1- (length s))) #\/))
                (subseq s 0 (1- (length s)))
                s))
         ;; Single-star suffix → recursive glob
         (s (cond
              ((and (>= (length s) 2)
                    (string= s "/*" :start1 (- (length s) 2))
                    (not (string= s "/**" :start1 (max 0 (- (length s) 3)))))
               (concatenate 'string (subseq s 0 (- (length s) 1)) "**"))
              (t s)))
         ;; Root "/" → "/**"
         (s (if (string= s "/") "/**" s)))
    s))

;;; ── Ops normalization ────────────────────────────────────────────────────────
;;; Sort alphabetically and remove duplicates for a stable canonical form.

(defun normalize-ops (op-set-obj)
  (let* ((deduped (remove-duplicates (ops op-set-obj) :test #'eq))
         (sorted  (sort (copy-list deduped) #'string<
                        :key (lambda (k) (symbol-name k)))))
    (make-instance 'op-set :ops sorted)))

;;; ── Conditions normalization ─────────────────────────────────────────────────
;;; Sort condition keys alphabetically; drop nil-valued keys (sugar for absent).

(defun normalize-conditions (cset)
  (unless cset (return-from normalize-conditions nil))
  (let* ((raw (condition-set-conditions cset))
         (pairs (loop for (k v) on raw by #'cddr
                      unless (null v) collect (cons k v)))
         (sorted (sort pairs #'string< :key (lambda (p) (symbol-name (car p)))))
         (plist (loop for (k . v) in sorted collect k collect v)))
    (if plist (apply #'condition-set plist) nil)))

;;; ── Resource normalization ───────────────────────────────────────────────────

(defun normalize-resource (resource)
  (etypecase resource
    (fs-resource
     (let* ((pat (path-glob-pattern (fs-resource-path resource)))
            (canonical (normalize-path-pattern pat)))
       (make-instance 'fs-resource :path (path-glob canonical))))
    (net-resource
     (make-instance 'net-resource
                    :host        (string-downcase (net-resource-host resource))
                    :path-prefix (let ((pp (net-resource-path-prefix resource)))
                                   (if (or (null pp) (string= pp "")) "/" pp))))
    ;; pid, ipc-fd, http: structural normalization only
    (pid-resource  resource)
    (ipc-fd-resource resource)
    (http-resource
     (make-instance 'http-resource
                    :url-pattern (normalize-path-pattern
                                  (http-resource-url-pattern resource))
                    :methods (normalize-ops (or (http-resource-methods resource)
                                                (op-set)))))))

(defmacro if-let ((var form) then else)
  `(let ((,var ,form))
     (if ,var ,then ,else)))

;;; ── Entry normalization ──────────────────────────────────────────────────────
;;; Also drops entries whose normalized op-set is empty (no-op grant).

(defun normalize-entry (entry)
  (let* ((res  (normalize-resource (entry-resource entry)))
         (ops  (normalize-ops (entry-ops entry)))
         (cond (normalize-conditions (entry-conditions entry))))
    (when (empty-op-set-p ops)
      (warn 'normalization-warning
            :message "entry has empty op-set after normalization; dropping"
            :form (class-name (class-of res))))
    (unless (empty-op-set-p ops)
      (make-instance 'authority-entry :resource res :ops ops :conditions cond))))

(defun normalize-entries (entries)
  "Normalize a list of entries, remove no-op entries, merge duplicates by resource."
  (let* ((normed (remove nil (mapcar #'normalize-entry entries)))
         (merged (merge-same-resource-entries normed)))
    (sort-entries merged)))

;;; Merge entries whose canonical resource string is identical: union ops,
;;; intersect conditions (keep tighter constraints — conservative for grant union).
(defun merge-same-resource-entries (entries)
  (let ((table (make-hash-table :test #'equal)))
    (dolist (e entries)
      (let ((key (resource-canonical-string (entry-resource e))))
        (if-let (existing (gethash key table))
          (setf (gethash key table) (merge-two-entries existing e))
          (setf (gethash key table) e))))
    (loop for v being the hash-values of table collect v)))

(defun merge-two-entries (a b)
  ;; Union ops; keep tighter conditions (nil cond = no restriction, so prefer non-nil).
  (make-instance 'authority-entry
                 :resource   (entry-resource a)
                 :ops        (op-set-union (entry-ops a) (entry-ops b))
                 :conditions (merge-conditions (entry-conditions a)
                                               (entry-conditions b))))

(defun merge-conditions (a b)
  ;; When merging two grants on the same resource, the combined grant is at
  ;; least as permissive as the more permissive individual grant on each key.
  (cond ((null a) nil)   ; no restriction from a side → no restriction overall
        ((null b) nil)
        (t
         (let* ((keys (union (loop for (k) on (condition-set-conditions a) by #'cddr collect k)
                             (loop for (k) on (condition-set-conditions b) by #'cddr collect k)))
                (merged (loop for k in keys
                              for va = (getf (condition-set-conditions a) k)
                              for vb = (getf (condition-set-conditions b) k)
                              for v  = (ecase k
                                         (:ttl        (and va vb (max va vb))) ; more permissive = longer
                                         (:quorum     (and va vb (min va vb))) ; more permissive = lower
                                         (:single-use (and va vb))             ; both must require
                                         (:audit      (and va vb)))
                              when v collect k and collect v)))
           (if merged (apply #'condition-set merged) nil)))))

;;; Sort entries: by provider keyword name, then by resource canonical string.
(defun sort-entries (entries)
  (sort (copy-list entries)
        #'entry<))

(defun entry< (a b)
  (let ((pa (symbol-name (resource-provider (entry-resource a))))
        (pb (symbol-name (resource-provider (entry-resource b)))))
    (if (string= pa pb)
        (string< (resource-canonical-string (entry-resource a))
                 (resource-canonical-string (entry-resource b)))
        (string< pa pb))))

;;; ── Node normalization ───────────────────────────────────────────────────────

(defun normalize-node (node)
  (make-instance 'cap-node
                 :principal (node-principal node)
                 :authority (normalize-entries (node-authority node))
                 :root      (node-root node)))

;;; ── Graph normalization ──────────────────────────────────────────────────────

(defun normalize-graph (graph)
  "Return a new AUTHORITY-GRAPH with all nodes and delegation authorities normalized."
  (let ((new-graph (make-authority-graph)))
    ;; Normalize every node.
    (maphash (lambda (_id node)
               (declare (ignore _id))
               (graph-add-node new-graph (normalize-node node)))
             (graph-nodes graph))
    ;; Normalize delegation authorities; preserve grantor/grantee.
    (dolist (edge (graph-delegations graph))
      (graph-add-delegation new-graph
        (make-instance 'delegation
                       :grantor   (delegation-grantor edge)
                       :grantee   (delegation-grantee edge)
                       :authority (normalize-entries (delegation-authority edge)))))
    new-graph))

;;; ── Canonical string form ────────────────────────────────────────────────────
;;; Deterministic s-expression string.  Callers can hash this for signing.
;;; resource-canonical-string is defined in ir.lisp (defgeneric + methods).

(defun canonicalize-entry (entry)
  "Return a deterministic string representing ENTRY.
   Two semantically identical entries (after normalization) produce the same string."
  (let ((normed (normalize-entry entry)))
    (when normed
      (with-output-to-string (s)
        (prin1
         `(entry ,(resource-provider (entry-resource normed))
                 ,(resource-canonical-string (entry-resource normed))
                 ,(mapcar #'symbol-name (ops (entry-ops normed)))
                 ,@(when (entry-conditions normed)
                     (list (condition-set-conditions (entry-conditions normed)))))
         s)))))

(defun canonicalize-node (node)
  "Return a deterministic string for NODE's principal + authority entries."
  (let ((normed (normalize-node node)))
    (with-output-to-string (s)
      (prin1
       `(node ,(principal-id (node-principal normed))
              ,@(mapcar #'canonicalize-entry (node-authority normed)))
       s))))

(defun canonicalize-graph (graph)
  "Return a deterministic string for the entire AUTHORITY-GRAPH.
   Nodes are ordered by principal-id; entries within each node are sorted."
  (let* ((normed   (normalize-graph graph))
         (node-ids (sort (loop for k being the hash-keys of (graph-nodes normed) collect k)
                         #'string<)))
    (with-output-to-string (s)
      (prin1
       `(authority-graph
         ,@(mapcar (lambda (id) (read-from-string (canonicalize-node (graph-node-for normed id))))
                   node-ids))
       s))))

;;; ── Hash functions ───────────────────────────────────────────────────────────
;;; If *hash-function* is set, returns hex string; otherwise returns the
;;; canonical string itself (useful for REPL inspection and unit tests).

(defun %apply-hash (canonical-string)
  (if *hash-function*
      (funcall *hash-function* canonical-string)
      canonical-string))

(defun hash-entry (entry)
  "Hash the canonical form of ENTRY.  Returns a hex string or canonical string."
  (%apply-hash (canonicalize-entry entry)))

(defun hash-node (node)
  "Hash the canonical form of NODE."
  (%apply-hash (canonicalize-node node)))

(defun hash-graph (graph)
  "Hash the canonical form of GRAPH."
  (%apply-hash (canonicalize-graph graph)))
