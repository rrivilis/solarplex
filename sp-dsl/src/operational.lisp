(defpackage #:authority-dsl/operational
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir #:authority-dsl/verifier)
  (:export
   ;; Effects — what can be committed
   #:effect #:effect-kind #:effect-resource-spec #:effect-payload
   #:fs-effect #:make-fs-effect
   #:process-effect #:make-process-effect
   #:net-effect #:make-net-effect
   #:ipc-effect #:make-ipc-effect
   #:http-effect #:make-http-effect
   #:effect-required-authority
   ;; Delta (receipt)
   #:delta #:delta-p #:delta-effect #:delta-authority #:delta-epoch
   #:delta-saga-id #:delta-sequence
   #:delta-before #:delta-after #:delta-timestamp
   #:make-delta
   ;; Session (principal + authority + epoch + history)
   #:session #:session-principal #:session-authority #:session-epoch #:session-deltas
   #:make-session #:session-push-delta #:session->scope
   ;; Scope environment
   #:*current-caps* #:*current-epoch*
   #:extend-caps #:scope-covers-p #:find-authorizing-cap
   ;; Saga hook points (set by saga.lisp at load time)
   #:*current-saga-id* #:*current-saga-sequence* #:*saga-commit-hook*
   ;; Runtime coordination primitives
   #:with-cap #:with-session #:commit! #:observe
   ;; Commitment error
   #:capability-error #:capability-error-effect #:capability-error-message
   ;; Static scope verifier
   #:static-scope-error #:static-scope-error-message #:static-scope-error-form
   #:verify-cap-scope
   ;; Replay invariant
   #:verify-replay-invariant #:deltas-equivalent-p
   ;; Serializer support — direct struct reconstruction without dynamic-var binding
   #:reconstruct-delta))

(in-package #:authority-dsl/operational)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; EFFECTS
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; An effect is a first-class description of a side effect.  commit! takes one,
;;; verifies authority in scope, and returns a delta.  The effect itself does not
;;; execute anything — it is a pure data description.
;;;
;;; This separates description (effect) from execution (the runtime that receives
;;; the delta and carries out the action, potentially after human approval).

(defclass effect ()
  ((kind          :initarg :kind          :reader effect-kind)          ; keyword
   (resource-spec :initarg :resource-spec :reader effect-resource-spec) ; string or structured
   (payload       :initarg :payload       :reader effect-payload        ; opaque content
                  :initform nil)))

(defclass fs-effect (effect) ()
  (:default-initargs :kind :fs))

(defclass process-effect (effect) ()
  (:default-initargs :kind :process))

(defclass net-effect (effect)
  ((method :initarg :method :reader net-effect-method :initform :connect))
  (:default-initargs :kind :net))

(defclass ipc-effect (effect) ()
  (:default-initargs :kind :ipc))

(defclass http-effect (effect)
  ((method :initarg :method :reader http-effect-method :initform :get))
  (:default-initargs :kind :http))

(defun make-fs-effect (op path &optional payload)
  "Construct an fs-effect.  OP is :read, :write, :delete, etc."
  (make-instance 'fs-effect :kind op :resource-spec path :payload payload))

(defun make-process-effect (op pid-ref &optional payload)
  (make-instance 'process-effect :kind op :resource-spec pid-ref :payload payload))

(defun make-net-effect (op host &optional payload)
  (make-instance 'net-effect :kind op :resource-spec host :payload payload :method op))

(defun make-ipc-effect (op fd &optional payload)
  (make-instance 'ipc-effect :kind op :resource-spec fd :payload payload))

(defun make-http-effect (method url &optional payload)
  (make-instance 'http-effect :kind method :resource-spec url :payload payload :method method))

;;; ── effect-required-authority ────────────────────────────────────────────────
;;; Maps an effect to the authority-entry it requires for authorization.
;;; This is the bridge between the effect layer and the IR authority layer.
;;; The verifier's covered-by-p can then be called directly.

(defgeneric effect-required-authority (effect)
  (:documentation "Return the AUTHORITY-ENTRY required to commit this EFFECT."))

(defmethod effect-required-authority ((e fs-effect))
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource
                                          :path (path-glob (effect-resource-spec e)))
                 :ops (op-set (effect-kind e))))

(defmethod effect-required-authority ((e process-effect))
  (make-instance 'authority-entry
                 :resource (make-instance 'pid-resource :ref (effect-resource-spec e))
                 :ops (op-set (effect-kind e))))

(defmethod effect-required-authority ((e net-effect))
  (make-instance 'authority-entry
                 :resource (make-instance 'net-resource :host (effect-resource-spec e))
                 :ops (op-set (effect-kind e))))

(defmethod effect-required-authority ((e ipc-effect))
  (make-instance 'authority-entry
                 :resource (make-instance 'ipc-fd-resource :fd (effect-resource-spec e))
                 :ops (op-set (effect-kind e))))

(defmethod effect-required-authority ((e http-effect))
  (make-instance 'authority-entry
                 :resource (make-instance 'http-resource
                                          :url-pattern (effect-resource-spec e)
                                          :methods (op-set (http-effect-method e)))
                 :ops (op-set (http-effect-method e))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; DELTA (RECEIPT)
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Every commit! produces a delta — the minimal record of what changed, under
;;; what authority, in what epoch.  The replay invariant: re-evaluating the
;;; same expression in the delta's before-state produces an equivalent delta.
;;;
;;; before/after are opaque identifiers (hashes, states, or mock values in tests).

(defstruct (delta (:constructor %make-delta-struct))
  effect         ; the effect that was committed
  authority      ; the authority-entry that authorized it
  epoch          ; the session epoch at commit time
  saga-id        ; nil, or the id of the enclosing saga
  sequence       ; 0, or the position of this delta in its saga-log
  before         ; state before the effect (hash, state-id, or :unknown)
  after          ; state after the effect (hash, state-id, or :unknown)
  timestamp)     ; universal-time at commit

(defun make-delta (effect authority-entry epoch &key (before :unknown) (after :unknown))
  (%make-delta-struct :effect    effect
                      :authority authority-entry
                      :epoch     epoch
                      :saga-id   *current-saga-id*
                      :sequence  *current-saga-sequence*
                      :before    before
                      :after     after
                      :timestamp (get-universal-time)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SESSION
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; A session is a principal's operational context: their identity, the authority
;;; they hold, the current epoch, and the history of committed deltas.
;;;
;;; "Construct a session view and observe inside the namespace" means:
;;;   (with-session alice-session
;;;     (observe "/data/alice/profile.json"))
;;; The session's authority IS the observation context — no separate auth lookup.

(defclass session ()
  ((principal :initarg :principal :reader session-principal :type string)
   (authority :initarg :authority :reader session-authority :type list)
   (epoch     :initarg :epoch     :reader session-epoch     :type integer :initform 0)
   (deltas    :accessor session-deltas                      :type list    :initform nil)))

(defun make-session (principal authority-entries &optional (epoch 0))
  "Construct a session for PRINCIPAL with AUTHORITY-ENTRIES and EPOCH."
  (make-instance 'session :principal principal :authority authority-entries :epoch epoch))

(defun session-push-delta (session delta)
  "Record a committed delta in SESSION's history."
  (push delta (session-deltas session))
  session)

(defun session->scope (session)
  "Project SESSION's authority into a list of authority-entry for scope binding."
  (session-authority session))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SCOPE ENVIRONMENT
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; *current-caps* is a dynamic variable holding the list of authority-entry
;;; values currently in scope.  with-cap extends it; commit! checks against it.
;;; This is lexical authority in the dynamic-binding sense — authority is visible
;;; to everything in the dynamic extent of with-cap, without explicit threading.

(defvar *current-caps* nil
  "Current capability scope: list of AUTHORITY-ENTRY values.
  Extended by WITH-CAP; read by COMMIT! and OBSERVE.")

(defvar *current-epoch* 0
  "Current session epoch.  Embedded in deltas for replay identification.")

;;; Saga hook points — nil outside a WITH-SAGA form.
;;; saga.lisp sets *saga-commit-hook* at load time to record deltas into the
;;; active saga-log without creating a circular package dependency.

(defvar *current-saga-id* nil
  "The id of the currently active saga, or NIL.")

(defvar *current-saga-sequence* 0
  "Monotonically increasing position counter within the current saga.")

(defvar *saga-commit-hook* nil
  "If non-nil, called (delta) after every successful COMMIT!.
  Set by saga.lisp to record the delta into the current saga-log.")

(defun extend-caps (current-caps new-entries)
  "Return a new scope extending CURRENT-CAPS with NEW-ENTRIES."
  (append new-entries current-caps))

(defun scope-covers-p (required-entry current-caps)
  "True iff REQUIRED-ENTRY is ⊑ some entry in CURRENT-CAPS."
  (some (lambda (cap) (authority-subset-p required-entry cap)) current-caps))

(defun find-authorizing-cap (required-entry current-caps)
  "Return the first entry in CURRENT-CAPS that covers REQUIRED-ENTRY, or NIL."
  (find-if (lambda (e) (authority-subset-p required-entry e)) current-caps))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; CAPABILITY ERROR
;;; ══════════════════════════════════════════════════════════════════════════════

(define-condition capability-error (error)
  ((effect  :initarg :effect  :reader capability-error-effect)
   (message :initarg :message :reader capability-error-message))
  (:report (lambda (c s)
             (format s "capability error: ~a [effect: ~a ~a]"
                     (capability-error-message c)
                     (effect-kind (capability-error-effect c))
                     (effect-resource-spec (capability-error-effect c))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; RUNTIME PRIMITIVES
;;; ══════════════════════════════════════════════════════════════════════════════

;;; ── with-cap ─────────────────────────────────────────────────────────────────
;;; Lexically scope a capability.  CAP is either a CAPABILITY object (parsed
;;; from a (cap ...) form), a list of AUTHORITY-ENTRY, or a SESSION.
;;;
;;; Authority is lexically bounded: anything evaluated in BODY can use the
;;; added authority; nothing outside this form can.

(defmacro with-cap (cap &body body)
  "Extend the current capability scope with CAP for the dynamic extent of BODY.
   CAP may be a CAPABILITY, SESSION, AUTHORITY-ENTRY, or a list thereof."
  `(let ((*current-caps* (extend-caps *current-caps* (%cap->entries ,cap))))
     ,@body))

(defun %cap->entries (cap)
  "Normalize various cap representations to a list of AUTHORITY-ENTRY."
  (etypecase cap
    (capability (cap-authority cap))
    (session    (session-authority cap))
    (authority-entry (list cap))
    (list       (if (every (lambda (x) (typep x 'authority-entry)) cap)
                    cap
                    (error "with-cap: expected a capability, session, entry, or entry list")))))

;;; ── with-session ─────────────────────────────────────────────────────────────
;;; Combine with-cap + epoch binding for a full session context.
;;; "Construct a session view and observe inside the namespace."

(defmacro with-session (session &body body)
  "Establish SESSION as the active authority namespace.
   Equivalent to (with-cap session ...) but also binds the epoch."
  `(let ((*current-caps* (extend-caps *current-caps* (session->scope ,session)))
         (*current-epoch* (session-epoch ,session)))
     ,@body))

;;; ── commit! ──────────────────────────────────────────────────────────────────
;;; Stage an effect.  Checks that the required authority is in scope, then
;;; returns a delta.  Does NOT execute the effect — the runtime that receives
;;; the delta decides whether to execute immediately or suspend for approval.
;;;
;;; "Effects suspend for human or automated resolution" — the delta IS the
;;; commitment.  The caller sends it to a guardian or executes it directly.

(defmacro commit! (effect-form &key before after)
  "Commit EFFECT-FORM within the current capability scope.
   Returns a DELTA (receipt).  Signals CAPABILITY-ERROR if authority is absent."
  `(%do-commit! ,effect-form :before ,before :after ,after))

(defun %do-commit! (effect &key before after)
  (let* ((required (effect-required-authority effect))
         (auth     (find-authorizing-cap required *current-caps*)))
    (unless auth
      (error 'capability-error
             :effect  effect
             :message (format nil "no authority in scope for ~a on ~a"
                              (effect-kind effect) (effect-resource-spec effect))))
    (let ((delta (make-delta effect auth *current-epoch*
                             :before (or before :unknown)
                             :after  (or after  :unknown))))
      ;; Advance saga sequence and notify the hook before returning.
      (when *current-saga-id*
        (incf *current-saga-sequence*))
      (when *saga-commit-hook*
        (funcall *saga-commit-hook* delta))
      delta)))

;;; ── observe ──────────────────────────────────────────────────────────────────
;;; Read a resource within the current authority namespace.
;;; Returns the resource value (or a mock).  Signals if no read authority.
;;; "You just construct a session view and observe inside the namespace."

(defun observe (resource-spec &key (op :read))
  "Read RESOURCE-SPEC within the current capability scope.
   OP defaults to :read.  Signals CAPABILITY-ERROR if read authority is absent."
  (let* ((required (make-instance 'authority-entry
                                  :resource (make-instance 'fs-resource
                                                           :path (path-glob resource-spec))
                                  :ops (op-set op)))
         (auth (find-authorizing-cap required *current-caps*)))
    (unless auth
      (error 'capability-error
             :effect  (make-fs-effect op resource-spec)
             :message (format nil "no authority to observe ~a" resource-spec)))
    ;; In a real runtime, this reads the actual resource.
    ;; Here we return a sentinel so tests can assert the call succeeded.
    (values :observed resource-spec)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; STATIC SCOPE VERIFIER
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Statically walk a cap-program form and verify that every commit! and observe
;;; call has covering authority in scope at that point.
;;;
;;; cap-program grammar:
;;;   expr ::= (with-cap cap expr*)
;;;          | (with-session session-expr expr*)
;;;          | (commit! effect-expr)
;;;          | (observe resource-string)
;;;          | (let ((var expr)*) expr*)
;;;          | (progn expr*)
;;;          | atom                         ; not analyzed
;;;
;;; The static verifier does not evaluate — it uses the cap-env threaded through
;;; the syntax to check commit!/observe at every static call site.

(define-condition static-scope-error (error)
  ((message  :initarg :message  :reader static-scope-error-message)
   (form     :initarg :form     :reader static-scope-error-form))
  (:report (lambda (c s)
             (format s "static scope error: ~a in ~s"
                     (static-scope-error-message c)
                     (static-scope-error-form c)))))

(defun verify-cap-scope (program &optional initial-caps)
  "Statically verify that all commit!/observe calls in PROGRAM have
   covering authority at their lexical site.  INITIAL-CAPS is a list of
   AUTHORITY-ENTRY representing ambient authority.
   Returns T on success; signals STATIC-SCOPE-ERROR on failure."
  (%verify-expr program (or initial-caps nil)))

(defun %verify-expr (expr cap-env)
  (unless (consp expr) (return-from %verify-expr t)) ; atom — skip
  (case (car expr)
    (with-cap
     ;; (with-cap cap-expr body...)
     ;; We cannot evaluate cap-expr statically in general, so we require it to
     ;; be a literal capability or authority-entry list.
     (let* ((cap-form (second expr))
            (body     (cddr expr))
            (entries  (if (typep cap-form 'list)
                          (mapcar #'%static-entry cap-form)
                          nil))
            (new-env  (extend-caps cap-env entries)))
       (dolist (b body) (%verify-expr b new-env))))
    (with-session
     ;; Cannot statically know session authority without evaluating — skip body.
     ;; In a full type system, session types would carry their authority statically.
     (dolist (b (cddr expr)) (%verify-expr b cap-env)))
    ((commit!)
     ;; (commit! effect-form) — check authority statically if effect is literal.
     (let ((effect-form (second expr)))
       (when (and (consp effect-form)
                  (member (car effect-form) '(make-fs-effect make-net-effect
                                              make-process-effect make-ipc-effect
                                              make-http-effect)))
         ;; We can partially evaluate the effect constructor to get a required entry.
         ;; This is a conservative check — real effects may differ at runtime.
         (let* ((mock-effect (%make-mock-effect effect-form))
                (required    (when mock-effect (effect-required-authority mock-effect))))
           (when (and required (not (scope-covers-p required cap-env)))
             (error 'static-scope-error
                    :message (format nil "commit! of ~a ~a has no covering authority in scope"
                                     (effect-kind mock-effect)
                                     (effect-resource-spec mock-effect))
                    :form expr))))))
    (observe
     ;; (observe resource-string)
     (let ((resource (second expr)))
       (when (stringp resource)
         (let* ((required (make-instance 'authority-entry
                                         :resource (make-instance 'fs-resource
                                                                  :path (path-glob resource))
                                         :ops (op-set :read))))
           (unless (scope-covers-p required cap-env)
             (error 'static-scope-error
                    :message (format nil "observe ~s has no covering :read authority in scope"
                                     resource)
                    :form expr))))))
    ((let let*)
     (let ((bindings (second expr))
           (body     (cddr expr)))
       (dolist (binding bindings)
         (when (consp binding) (%verify-expr (second binding) cap-env)))
       (dolist (b body) (%verify-expr b cap-env))))
    (progn
     (dolist (b (cdr expr)) (%verify-expr b cap-env)))
    (otherwise
     ;; Unknown form — recurse into subforms.
     (dolist (sub (cdr expr))
       (when (consp sub) (%verify-expr sub cap-env)))))
  t)

(defun %make-mock-effect (form)
  "Partially evaluate a make-*-effect call to get a mock effect for static analysis."
  (handler-case
      (case (car form)
        (make-fs-effect      (make-fs-effect      (second form) (third form)))
        (make-net-effect     (make-net-effect     (second form) (third form)))
        (make-process-effect (make-process-effect (second form) (third form)))
        (make-ipc-effect     (make-ipc-effect     (second form) (third form)))
        (make-http-effect    (make-http-effect    (second form) (third form))))
    (error () nil)))

(defun %static-entry (x)
  "If X is an AUTHORITY-ENTRY, return it.  Otherwise nil."
  (when (typep x 'authority-entry) x))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; REPLAY INVARIANT
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Replay eval invariant: every evaluation produces a delta; re-evaluation
;;; from that delta is definitionally equivalent.
;;;
;;; Formally: if D = commit!(e, state_before) then
;;;   D.effect   = e
;;;   D.before   = state_before
;;;   D.after    = apply(e, state_before)
;;;   D.epoch    = current epoch
;;;
;;; Two deltas are EQUIVALENT if their effects describe the same operation on
;;; the same resource with the same payload.  Before/after states are checked
;;; only when both are known (not :unknown).
;;;
;;; Replay check: given a delta D and an expression E, re-run E in a scope where
;;; D's authority is available and assert the resulting delta is equivalent to D.

(defun deltas-equivalent-p (d1 d2)
  "True iff D1 and D2 represent equivalent committed effects.
   Effects match if kind, resource, and payload agree.
   Before/after states match if both are known and equal, or either is :unknown."
  (and (eq (effect-kind          (delta-effect d1))
           (effect-kind          (delta-effect d2)))
       (equal (effect-resource-spec (delta-effect d1))
              (effect-resource-spec (delta-effect d2)))
       (equal (effect-payload       (delta-effect d1))
              (effect-payload       (delta-effect d2)))
       (= (delta-epoch d1) (delta-epoch d2))
       (%states-match-p (delta-before d1) (delta-before d2))
       (%states-match-p (delta-after  d1) (delta-after  d2))))

(defun %states-match-p (s1 s2)
  (or (eq s1 :unknown) (eq s2 :unknown) (equal s1 s2)))

;;; ── reconstruct-delta ────────────────────────────────────────────────────────
;;; Used by the serializer to rebuild a delta from wire data without needing
;;; to bind the dynamic saga vars or patch the timestamp after the fact.

(defun reconstruct-delta (effect authority epoch saga-id sequence before after timestamp)
  "Directly construct a DELTA from deserialized fields.
   Does not go through MAKE-DELTA or require dynamic variable binding."
  (%make-delta-struct
   :effect    effect
   :authority authority
   :epoch     (or epoch 0)
   :saga-id   saga-id
   :sequence  (or sequence 0)
   :before    (or before :unknown)
   :after     (or after  :unknown)
   :timestamp (or timestamp 0)))

(defun verify-replay-invariant (original-delta thunk &key epoch)
  "Verify the replay invariant for ORIGINAL-DELTA.
   THUNK is a zero-argument function that produces a new delta by re-evaluating
   the original expression.  The new delta must be equivalent to ORIGINAL-DELTA.
   EPOCH defaults to the original delta's epoch."
  (let* ((*current-epoch* (or epoch (delta-epoch original-delta)))
         (*current-caps*  (list (delta-authority original-delta)))
         (replay-delta    (funcall thunk)))
    (unless (deltas-equivalent-p original-delta replay-delta)
      (error "replay invariant violated: ~
              original ~a ~a ≠ replay ~a ~a"
             (effect-kind (delta-effect original-delta))
             (effect-resource-spec (delta-effect original-delta))
             (effect-kind (delta-effect replay-delta))
             (effect-resource-spec (delta-effect replay-delta))))
    t))
