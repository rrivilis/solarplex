(defpackage #:authority-dsl/ir
  (:use #:cl #:authority-dsl/algebra)
  (:export
   ;; Resources
   #:resource #:resource-provider
   #:fs-resource #:fs-resource-path
   #:net-resource #:net-resource-host #:net-resource-path-prefix
   #:net-resource-port-min #:net-resource-port-max
   #:pid-resource #:pid-resource-ref
   #:ipc-fd-resource #:ipc-fd-resource-fd
   #:http-resource #:http-resource-url-pattern #:http-resource-methods
   #:wasm-resource #:wasm-resource-module
   ;; Root authority
   #:root-authority #:root-kind #:root-provider #:root-provenance
   ;; Authority entries
   #:authority-entry #:entry-resource #:entry-ops #:entry-conditions
   ;; entry→dims projection (algebra contract)
   #:entry->dims
   ;; Principals
   #:principal #:principal-id
   ;; Nodes
   #:cap-node #:node-principal #:node-authority #:node-root
   ;; Delegation edges
   #:delegation #:delegation-grantor #:delegation-grantee #:delegation-authority
   ;; Graph
   #:authority-graph #:graph-nodes #:graph-delegations #:graph-roots
   #:make-authority-graph
   #:graph-add-node #:graph-add-delegation
   #:graph-node-for #:graph-authority-of
   ;; Verification predicate (plain function — not a generic; backends cannot override)
   #:authority-subset-p
   ;; Structural identity (not used by verifier; available for tooling)
   #:resource-subset-p
   #:resource-canonical-string
   ;; Capability document (self-contained delegation unit)
   #:capability #:cap-action #:cap-subject #:cap-authority
   #:cap-derived-from #:cap-conditions #:cap-metadata
   #:capability->delegation))

(in-package #:authority-dsl/ir)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; RESOURCE TYPES
;;; ══════════════════════════════════════════════════════════════════════════════

(defclass resource ()
  ((provider :initarg :provider :reader resource-provider :type keyword)))

(defclass fs-resource (resource)
  ((path :initarg :path :reader fs-resource-path))   ; path-glob
  (:default-initargs :provider :linux-fs))

(defclass net-resource (resource)
  ((host        :initarg :host        :reader net-resource-host)
   (port-min    :initarg :port-min    :reader net-resource-port-min :initform 0)
   (port-max    :initarg :port-max    :reader net-resource-port-max :initform 65535)
   (path-prefix :initarg :path-prefix :reader net-resource-path-prefix :initform "/"))
  (:default-initargs :provider :linux-net))

(defclass pid-resource (resource)
  ((ref :initarg :ref :reader pid-resource-ref))   ; :any | integer pidfd
  (:default-initargs :provider :linux-pid))

(defclass ipc-fd-resource (resource)
  ((fd :initarg :fd :reader ipc-fd-resource-fd))   ; :any | integer fd
  (:default-initargs :provider :ipc-fd))

(defclass http-resource (resource)
  ((url-pattern :initarg :url-pattern :reader http-resource-url-pattern)
   (methods     :initarg :methods     :reader http-resource-methods :initform nil))
  (:default-initargs :provider :http-ucan))

(defclass wasm-resource (resource)
  ((module :initarg :module :reader wasm-resource-module))  ; string | "*"
  (:default-initargs :provider :wasm))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; ROOT AUTHORITY
;;; ══════════════════════════════════════════════════════════════════════════════
;;; The verifier does not re-validate how a root was established.  Root kind
;;; is informational for audit; monotonicity proofs are kind-agnostic.

(defclass root-authority ()
  ((kind       :initarg :kind       :reader root-kind)       ; :ambient-os | :certificate | :administrative
   (provider   :initarg :provider   :reader root-provider)
   (provenance :initarg :provenance :reader root-provenance :initform nil)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; AUTHORITY ENTRIES
;;; ══════════════════════════════════════════════════════════════════════════════

(defclass authority-entry ()
  ((resource   :initarg :resource   :reader entry-resource)
   (ops        :initarg :ops        :reader entry-ops)        ; op-set
   (conditions :initarg :conditions :reader entry-conditions  ; condition-set or nil
               :initform nil)))

;;; ── entry->dims: projection to algebra's plist contract ──────────────────────
;;; This is the ONLY interface between the IR layer and algebra's lattice
;;; predicates.  Each method extracts the provider-specific dimensions from an
;;; authority-entry so that lattice-subset-p can work on pure data.
;;;
;;; Adding a new resource type: define a new resource class above and add an
;;; entry->dims method here.  The verifier requires nothing else.

(defgeneric entry->dims (entry)
  (:documentation "Project ENTRY into the algebra dims plist for its provider."))

(defmethod entry->dims ((e authority-entry))
  (let ((r (entry-resource e))
        (o (ops (entry-ops e)))
        (c (entry-conditions e)))
    (etypecase r
      (fs-resource
       (list :path       (path-glob-pattern (fs-resource-path r))
             :ops        o
             :conditions c))
      (net-resource
       (list :host       (net-resource-host r)
             :port-min   (net-resource-port-min r)
             :port-max   (net-resource-port-max r)
             :path-prefix (net-resource-path-prefix r)
             :ops        o
             :conditions c))
      (pid-resource
       (list :ref        (pid-resource-ref r)
             :ops        o
             :conditions c))
      (ipc-fd-resource
       (list :fd         (ipc-fd-resource-fd r)
             :ops        o
             :conditions c))
      (http-resource
       (list :url        (http-resource-url-pattern r)
             :methods    (when (http-resource-methods r)
                           (ops (http-resource-methods r)))
             :conditions c))
      (wasm-resource
       (list :module     (wasm-resource-module r)
             :ops        o
             :conditions c)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; AUTHORITY-SUBSET-P — the verification predicate
;;; ══════════════════════════════════════════════════════════════════════════════
;;; This is a plain DEFUN, not a DEFGENERIC.  Backends lower IR to native
;;; representations; they do not override what subset means.  All subset logic
;;; lives in algebra.lisp's registered predicates.

(defun authority-subset-p (child parent)
  "True iff CHILD-ENTRY grants no more authority than PARENT-ENTRY.
   Dispatches through algebra's provider lattice registry.
   Returns NIL (not an error) if providers differ — mismatched providers
   are never in a subset relation."
  (let ((cp (resource-provider (entry-resource child)))
        (pp (resource-provider (entry-resource parent))))
    (and (eq cp pp)
         (lattice-subset-p cp (entry->dims child) (entry->dims parent)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; STRUCTURAL RESOURCE IDENTITY
;;; ══════════════════════════════════════════════════════════════════════════════
;;; resource-subset-p and resource-canonical-string are structural utilities
;;; for tooling (normalizer merging, canonical hashing).  They are NOT used
;;; by the verifier — authority-subset-p goes through entry->dims + lattice-subset-p.

(defgeneric resource-subset-p (child parent)
  (:documentation "Structural containment check for normalizer merging.
  NOT used by authority-subset-p; backed by algebra's path/port predicates."))

(defmethod resource-subset-p ((child fs-resource) (parent fs-resource))
  (path-glob-subset-p (fs-resource-path child) (fs-resource-path parent)))

(defmethod resource-subset-p ((child net-resource) (parent net-resource))
  (and (or (string= (net-resource-host parent) "*")
           (string= (net-resource-host child) (net-resource-host parent)))
       (port-range-subset-p
        (port-range (net-resource-port-min child) (net-resource-port-max child))
        (port-range (net-resource-port-min parent) (net-resource-port-max parent)))
       (let ((pp (net-resource-path-prefix parent))
             (cp (net-resource-path-prefix child)))
         (or (string= pp "/")
             (and (<= (length pp) (length cp))
                  (string= cp pp :end1 (length pp)))))))

(defmethod resource-subset-p ((child pid-resource) (parent pid-resource))
  (or (eq (pid-resource-ref parent) :any)
      (equal (pid-resource-ref child) (pid-resource-ref parent))))

(defmethod resource-subset-p ((child ipc-fd-resource) (parent ipc-fd-resource))
  (or (eq (ipc-fd-resource-fd parent) :any)
      (equal (ipc-fd-resource-fd child) (ipc-fd-resource-fd parent))))

(defmethod resource-subset-p ((child http-resource) (parent http-resource))
  (and (path-glob-subset-p (path-glob (http-resource-url-pattern child))
                           (path-glob (http-resource-url-pattern parent)))
       (op-set-subset-p (or (http-resource-methods child) (op-set))
                        (or (http-resource-methods parent) (op-set)))))

(defmethod resource-subset-p ((child wasm-resource) (parent wasm-resource))
  (or (string= (wasm-resource-module parent) "*")
      (string= (wasm-resource-module child) (wasm-resource-module parent))))

(defgeneric resource-canonical-string (resource)
  (:documentation "Deterministic string key for RESOURCE.  Used by normalizer."))

(defmethod resource-canonical-string ((r fs-resource))
  (path-glob-pattern (fs-resource-path r)))

(defmethod resource-canonical-string ((r net-resource))
  (format nil "~a:~a-~a~a"
          (net-resource-host r)
          (net-resource-port-min r)
          (net-resource-port-max r)
          (net-resource-path-prefix r)))

(defmethod resource-canonical-string ((r pid-resource))
  (format nil "pid:~a" (pid-resource-ref r)))

(defmethod resource-canonical-string ((r ipc-fd-resource))
  (format nil "fd:~a" (ipc-fd-resource-fd r)))

(defmethod resource-canonical-string ((r http-resource))
  (http-resource-url-pattern r))

(defmethod resource-canonical-string ((r wasm-resource))
  (format nil "wasm:~a" (wasm-resource-module r)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; PRINCIPALS, NODES, EDGES, GRAPH
;;; ══════════════════════════════════════════════════════════════════════════════

(defclass principal ()
  ((id :initarg :id :reader principal-id :type string)))

(defclass cap-node ()
  ((principal :initarg :principal :reader node-principal)
   (authority :initarg :authority :reader node-authority :initform nil)
   (root      :initarg :root      :reader node-root      :initform nil)))

(defclass delegation ()
  ((grantor   :initarg :grantor   :reader delegation-grantor)
   (grantee   :initarg :grantee   :reader delegation-grantee)
   (authority :initarg :authority :reader delegation-authority)))

(defclass authority-graph ()
  ((nodes       :initform (make-hash-table :test #'equal) :reader graph-nodes)
   (delegations :initform nil                              :accessor graph-delegations)
   (roots       :initform nil                              :accessor graph-roots)))

(defun make-authority-graph ()
  (make-instance 'authority-graph))

(defun graph-add-node (graph node)
  (setf (gethash (principal-id (node-principal node)) (graph-nodes graph)) node)
  (when (node-root node) (push node (graph-roots graph)))
  graph)

(defun graph-add-delegation (graph delegation)
  (push delegation (graph-delegations graph))
  graph)

(defun graph-node-for (graph principal-id)
  (gethash principal-id (graph-nodes graph)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; CAPABILITY DOCUMENT
;;; ══════════════════════════════════════════════════════════════════════════════
;;; A self-contained delegation unit, as opposed to the graph which is a
;;; collection of nodes and edges.  A (cap delegate ...) form produces one of
;;; these.  Multiple capabilities can be assembled into an authority-graph via
;;; CAPABILITY->DELEGATION.
;;;
;;; Actions:
;;;   :delegate — the subject is being granted authority derived from derived-from
;;;   :invoke   — the subject is invoking a specific method (not yet used)

(defclass capability ()
  ((action       :initarg :action       :reader cap-action)       ; :delegate | :invoke
   (subject      :initarg :subject      :reader cap-subject)      ; string principal-id
   (authority    :initarg :authority    :reader cap-authority)    ; list of authority-entry
   (derived-from :initarg :derived-from :reader cap-derived-from  ; string or nil
                 :initform nil)
   (conditions   :initarg :conditions   :reader cap-conditions    ; condition-set or nil
                 :initform nil)
   (metadata     :initarg :metadata     :reader cap-metadata      ; opaque plist
                 :initform nil)))

(defun capability->delegation (cap grantor-id)
  "Lift a CAPABILITY into a DELEGATION edge from GRANTOR-ID to the cap's subject.
   Conditions on the capability are attached to each authority entry."
  (let* ((cset (cap-conditions cap))
         (entries (if cset
                      (mapcar (lambda (e)
                                (make-instance 'authority-entry
                                               :resource   (entry-resource e)
                                               :ops        (entry-ops e)
                                               :conditions (or (entry-conditions e) cset)))
                              (cap-authority cap))
                      (cap-authority cap))))
    (make-instance 'delegation
                   :grantor   (or (cap-derived-from cap) grantor-id)
                   :grantee   (cap-subject cap)
                   :authority entries)))

(defun graph-authority-of (graph principal-id)
  (let ((node (graph-node-for graph principal-id)))
    (when node (node-authority node))))
