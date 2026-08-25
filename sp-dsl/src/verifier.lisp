(defpackage #:authority-dsl/verifier
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir)
  (:export
   #:verify-graph
   #:verify-delegation
   #:verification-result
   #:result-ok-p
   #:result-errors
   #:verification-error))

(in-package #:authority-dsl/verifier)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; VERIFIER — backend independence contract
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; This package imports only ALGEBRA and IR.  It must never import a backend
;;; package (linux, wasm, ucan, etc.).  Backend knowledge belongs in lowering
;;; passes that run AFTER verification, not inside the monotonicity check.
;;;
;;; The single verification predicate is:
;;;
;;;   Γ ⊢ delegate(A, B)  iff  ∀ entry e ∈ authority(B):
;;;     ∃ entry p ∈ authority(A): authority-subset-p(e, p)
;;;
;;; AUTHORITY-SUBSET-P is a plain function in ir.lisp that dispatches through
;;; algebra's *provider-lattices* registry.  Backends cannot override it.
;;;
;;; Cross-provider amplification (known open gap):
;;;   Per-provider monotonicity does not catch transitive information leakage
;;;   across provider boundaries (e.g. fs.read /proc/net grants net topology
;;;   information).  This is documented in THREAT_MODEL.md §11.1 and is a
;;;   property of the deployment, not the DSL.  The verifier correctly rejects
;;;   cross-provider subset attempts (different providers → authority-subset-p
;;;   returns NIL), but it does not model semantic cross-provider channels.

;;; ── Result type ──────────────────────────────────────────────────────────────

(defstruct (verification-result (:conc-name result-))
  (ok-p t :type boolean)
  (errors nil :type list))

(define-condition verification-error (error)
  ((message :initarg :message :reader verification-error-message)
   (grantor :initarg :grantor :reader verification-error-grantor :initform nil)
   (grantee :initarg :grantee :reader verification-error-grantee :initform nil))
  (:report (lambda (c s)
             (format s "authority verification failed~@[ (~a → ~a)~]: ~a"
                     (verification-error-grantor c)
                     (verification-error-grantee c)
                     (verification-error-message c)))))

;;; ── Graph-level verification ──────────────────────────────────────────────────

(defun verify-graph (graph)
  "Check all delegation edges in GRAPH.  Returns VERIFICATION-RESULT."
  (let (errors)
    (dolist (edge (graph-delegations graph))
      (setf errors (nconc errors (check-edge graph edge))))
    (make-verification-result :ok-p (null errors) :errors errors)))

(defun check-edge (graph edge)
  "Returns a list of error strings for EDGE (empty = valid)."
  (let* ((grantor-id   (delegation-grantor edge))
         (grantee-id   (delegation-grantee edge))
         (grantor-auth (graph-authority-of graph grantor-id)))
    (unless grantor-auth
      (return-from check-edge
        (list (format nil "grantor ~s not found in graph" grantor-id))))
    (loop for child-entry in (delegation-authority edge)
          unless (covered-by-p child-entry grantor-auth)
          collect (format nil "~s → ~s: [~a ~a] not covered by grantor authority"
                          grantor-id grantee-id
                          (class-name (class-of (entry-resource child-entry)))
                          (ops (entry-ops child-entry))))))

(defun covered-by-p (child-entry grantor-authority-list)
  "True iff CHILD-ENTRY is ⊑ some entry in GRANTOR-AUTHORITY-LIST."
  (some (lambda (parent-entry)
          ;; authority-subset-p returns NIL for mismatched providers;
          ;; no handler-case needed since it never signals for provider mismatch.
          (authority-subset-p child-entry parent-entry))
        grantor-authority-list))

;;; ── Single delegation check ──────────────────────────────────────────────────

(defun verify-delegation (grantor-entries grantee-entries &key grantor-id grantee-id)
  "Check that every entry in GRANTEE-ENTRIES is covered by GRANTOR-ENTRIES."
  (let (errors)
    (dolist (child-entry grantee-entries)
      (unless (covered-by-p child-entry grantor-entries)
        (push (format nil "~@[~a → ~a: ~]~a violates monotonic attenuation"
                      grantor-id grantee-id
                      (class-name (class-of (entry-resource child-entry))))
              errors)))
    (make-verification-result :ok-p (null errors) :errors errors)))

;;; ── Strict mode ──────────────────────────────────────────────────────────────

(defun verify-graph! (graph)
  "Like VERIFY-GRAPH but signals VERIFICATION-ERROR on the first failure."
  (dolist (edge (graph-delegations graph))
    (let ((errors (check-edge graph edge)))
      (when errors
        (error 'verification-error
               :grantor (delegation-grantor edge)
               :grantee (delegation-grantee edge)
               :message (first errors)))))
  t)
