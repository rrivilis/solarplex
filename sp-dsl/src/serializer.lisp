(defpackage #:authority-dsl/serializer
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir
        #:authority-dsl/operational #:authority-dsl/saga)
  (:export
   ;; Serialize to s-expression
   #:serialize
   ;; Deserialize from s-expression
   #:deserialize
   ;; String round-trip
   #:serialize-to-string
   #:deserialize-from-string))

(in-package #:authority-dsl/serializer)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SERIALIZE
;;;
;;; Convert any DSL object to a portable, READ-able s-expression.
;;; All output is pure lists, keywords, strings, integers, and symbols —
;;; nothing that requires a running image to read back.
;;;
;;; Tagged format: (:type-tag :slot value ...)
;;; Primitives pass through unchanged.
;;; ══════════════════════════════════════════════════════════════════════════════

(defgeneric serialize (object)
  (:documentation "Convert OBJECT to a portable s-expression."))

;;; Primitives pass through.
(defmethod serialize ((x null))    nil)
(defmethod serialize ((x symbol))  x)
(defmethod serialize ((x number))  x)
(defmethod serialize ((x string))  x)
(defmethod serialize ((x list))    (mapcar #'serialize x))

;;; ── Algebra types ────────────────────────────────────────────────────────────

(defmethod serialize ((os op-set))
  (ops os))  ; already a list of keywords

(defmethod serialize ((pg path-glob))
  (path-glob-pattern pg))

(defmethod serialize ((cs condition-set))
  ;; Conditions is a flat plist — values are primitives or symbol lists.
  ;; Serialize each value element; keys are already keywords.
  (loop for (key val) on (condition-set-conditions cs) by #'cddr
        nconc (list key (serialize val))))

;;; ── Resources ────────────────────────────────────────────────────────────────

(defmethod serialize ((r fs-resource))
  `(:fs :path ,(path-glob-pattern (fs-resource-path r))))

(defmethod serialize ((r net-resource))
  `(:net :host      ,(net-resource-host r)
         :port-min  ,(net-resource-port-min r)
         :port-max  ,(net-resource-port-max r)
         :path-prefix ,(net-resource-path-prefix r)))

(defmethod serialize ((r pid-resource))
  `(:pid :ref ,(pid-resource-ref r)))

(defmethod serialize ((r ipc-fd-resource))
  `(:ipc-fd :fd ,(ipc-fd-resource-fd r)))

(defmethod serialize ((r http-resource))
  `(:http :url     ,(http-resource-url-pattern r)
          :methods ,(when (http-resource-methods r)
                      (ops (http-resource-methods r)))))

(defmethod serialize ((r wasm-resource))
  `(:wasm :module ,(wasm-resource-module r)))

;;; ── IR types ─────────────────────────────────────────────────────────────────

(defmethod serialize ((e authority-entry))
  `(:entry
    :resource   ,(serialize (entry-resource e))
    :ops        ,(ops (entry-ops e))
    :conditions ,(when (entry-conditions e)
                   (serialize (entry-conditions e)))))

(defmethod serialize ((d delegation))
  `(:delegation
    :grantor   ,(delegation-grantor d)
    :grantee   ,(delegation-grantee d)
    :authority ,(mapcar #'serialize (delegation-authority d))))

(defmethod serialize ((c capability))
  `(:capability
    :action       ,(cap-action c)
    :subject      ,(cap-subject c)
    :authority    ,(mapcar #'serialize (cap-authority c))
    :derived-from ,(cap-derived-from c)
    :conditions   ,(when (cap-conditions c) (serialize (cap-conditions c)))
    :metadata     ,(cap-metadata c)))

;;; ── Operational types ────────────────────────────────────────────────────────

(defmethod serialize ((e effect))
  `(:effect
    :kind         ,(effect-kind e)
    :resource-spec ,(effect-resource-spec e)
    :payload      ,(effect-payload e)))

(defmethod serialize ((d delta))
  `(:delta
    :effect    ,(serialize (delta-effect d))
    :authority ,(serialize (delta-authority d))
    :epoch     ,(delta-epoch d)
    :saga-id   ,(delta-saga-id d)
    :sequence  ,(delta-sequence d)
    :before    ,(delta-before d)
    :after     ,(delta-after d)
    :timestamp ,(delta-timestamp d)))

;;; ── Saga types ───────────────────────────────────────────────────────────────

(defmethod serialize ((r transfer-receipt))
  `(:transfer-receipt
    :saga-id   ,(transfer-receipt-saga-id r)
    :sequence  ,(transfer-receipt-sequence r)
    :grantor   ,(transfer-receipt-grantor r)
    :recipient ,(transfer-receipt-recipient r)
    :authority ,(mapcar #'serialize (transfer-receipt-authority r))
    :timestamp ,(transfer-receipt-timestamp r)))

(defmethod serialize ((r send-receipt))
  `(:send-receipt
    :saga-id      ,(send-receipt-saga-id r)
    :sequence     ,(send-receipt-sequence r)
    :sender       ,(send-receipt-sender r)
    :recipient    ,(send-receipt-recipient r)
    :message-kind ,(send-receipt-message-kind r)
    :timestamp    ,(send-receipt-timestamp r)))

(defmethod serialize ((e saga-log-entry))
  `(:saga-log-entry
    :kind      ,(saga-log-entry-kind e)
    :sequence  ,(saga-log-entry-sequence e)
    :payload   ,(serialize (saga-log-entry-payload e))
    :timestamp ,(saga-log-entry-timestamp e)))

(defmethod serialize ((log saga-log))
  `(:saga-log
    :saga-id ,(saga-log-saga-id log)
    :entries ,(mapcar #'serialize (saga-log-entries log))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; DESERIALIZE
;;;
;;; Reconstruct a DSL object from a serialized s-expression.
;;; Dispatches on the type tag (first element).
;;; ══════════════════════════════════════════════════════════════════════════════

(defun deserialize (sexp)
  "Reconstruct a DSL object from a tagged s-expression produced by SERIALIZE."
  (if (or (null sexp) (atom sexp))
      sexp  ; primitive — return as-is
      (destructuring-bind (tag &rest plist) sexp
        (%deserialize tag plist))))

(defun %get (plist key)
  (getf plist key))

(defgeneric %deserialize (tag plist)
  (:documentation "Dispatch deserialization by type tag."))

;;; ── Algebra ──────────────────────────────────────────────────────────────────

(defmethod %deserialize ((tag (eql :fs)) plist)
  (make-instance 'fs-resource :path (path-glob (%get plist :path))))

(defmethod %deserialize ((tag (eql :net)) plist)
  (make-instance 'net-resource
                 :host        (%get plist :host)
                 :port-min    (or (%get plist :port-min) 0)
                 :port-max    (or (%get plist :port-max) 65535)
                 :path-prefix (or (%get plist :path-prefix) "/")))

(defmethod %deserialize ((tag (eql :pid)) plist)
  (make-instance 'pid-resource :ref (%get plist :ref)))

(defmethod %deserialize ((tag (eql :ipc-fd)) plist)
  (make-instance 'ipc-fd-resource :fd (%get plist :fd)))

(defmethod %deserialize ((tag (eql :http)) plist)
  (make-instance 'http-resource
                 :url-pattern (%get plist :url)
                 :methods     (let ((ms (%get plist :methods)))
                                (when ms (apply #'op-set ms)))))

(defmethod %deserialize ((tag (eql :wasm)) plist)
  (make-instance 'wasm-resource :module (%get plist :module)))

;;; ── IR ───────────────────────────────────────────────────────────────────────

(defmethod %deserialize ((tag (eql :entry)) plist)
  (let* ((resource   (deserialize (%get plist :resource)))
         (ops-list   (%get plist :ops))
         (cond-plist (%get plist :conditions)))
    (make-instance 'authority-entry
                   :resource   resource
                   :ops        (apply #'op-set ops-list)
                   :conditions (when cond-plist
                                 (make-instance 'condition-set :conditions cond-plist)))))

(defmethod %deserialize ((tag (eql :delegation)) plist)
  (make-instance 'delegation
                 :grantor   (%get plist :grantor)
                 :grantee   (%get plist :grantee)
                 :authority (mapcar #'deserialize (%get plist :authority))))

(defmethod %deserialize ((tag (eql :capability)) plist)
  (make-instance 'capability
                 :action       (%get plist :action)
                 :subject      (%get plist :subject)
                 :authority    (mapcar #'deserialize (%get plist :authority))
                 :derived-from (%get plist :derived-from)
                 :conditions   (let ((c (%get plist :conditions)))
                                 (when c (make-instance 'condition-set :conditions c)))
                 :metadata     (%get plist :metadata)))

;;; ── Operational ──────────────────────────────────────────────────────────────

(defmethod %deserialize ((tag (eql :effect)) plist)
  (make-instance 'effect
                 :kind          (%get plist :kind)
                 :resource-spec (%get plist :resource-spec)
                 :payload       (%get plist :payload)))

(defmethod %deserialize ((tag (eql :delta)) plist)
  (reconstruct-delta
   (deserialize (%get plist :effect))
   (deserialize (%get plist :authority))
   (%get plist :epoch)
   (%get plist :saga-id)
   (%get plist :sequence)
   (%get plist :before)
   (%get plist :after)
   (%get plist :timestamp)))

;;; ── Saga ─────────────────────────────────────────────────────────────────────

(defmethod %deserialize ((tag (eql :transfer-receipt)) plist)
  (make-transfer-receipt-from-parts
   :saga-id   (%get plist :saga-id)
   :sequence  (%get plist :sequence)
   :grantor   (%get plist :grantor)
   :recipient (%get plist :recipient)
   :authority (mapcar #'deserialize (%get plist :authority))
   :timestamp (%get plist :timestamp)))

(defmethod %deserialize ((tag (eql :send-receipt)) plist)
  (make-send-receipt-from-parts
   :saga-id      (%get plist :saga-id)
   :sequence     (%get plist :sequence)
   :sender       (%get plist :sender)
   :recipient    (%get plist :recipient)
   :message-kind (%get plist :message-kind)
   :timestamp    (%get plist :timestamp)))

(defmethod %deserialize ((tag (eql :saga-log-entry)) plist)
  (make-saga-log-entry-from-parts
   :kind      (%get plist :kind)
   :sequence  (%get plist :sequence)
   :payload   (deserialize (%get plist :payload))
   :timestamp (%get plist :timestamp)))

(defmethod %deserialize ((tag (eql :saga-log)) plist)
  (let ((log (make-saga-log (%get plist :saga-id))))
    (dolist (entry-sexp (%get plist :entries))
      (saga-log-push-entry! log (deserialize entry-sexp)))
    log))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; STRING ROUND-TRIP
;;; ══════════════════════════════════════════════════════════════════════════════

(defun serialize-to-string (object)
  "Serialize OBJECT to a self-contained, READ-able string."
  (with-output-to-string (s)
    (write (serialize object) :stream s :readably t)))

(defun deserialize-from-string (str)
  "Deserialize a DSL object from a string produced by SERIALIZE-TO-STRING."
  (deserialize (read-from-string str)))
