(defpackage #:authority-dsl/tests/serializer
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir
        #:authority-dsl/operational #:authority-dsl/saga
        #:authority-dsl/serializer))

(in-package #:authority-dsl/tests/serializer)

(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (label form)
  `(if ,form
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a~%" ,label))))

(defun %fs-entry (path &rest ops)
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource :path (path-glob path))
                 :ops (apply #'op-set ops)))

;;; ── Round-trip helper ────────────────────────────────────────────────────────

(defun round-trip (object)
  "Serialize OBJECT to a string, then deserialize back."
  (deserialize-from-string (serialize-to-string object)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 1. Resources
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-serialize-resources ()
  (let* ((fs   (make-instance 'fs-resource :path (path-glob "/data/**")))
         (net  (make-instance 'net-resource :host "example.com"
                              :port-min 443 :port-max 443 :path-prefix "/api"))
         (pid  (make-instance 'pid-resource :ref 1234))
         (ipc  (make-instance 'ipc-fd-resource :fd 7))
         (http (make-instance 'http-resource :url-pattern "https://api.example.com/**"
                              :methods (op-set :get :post)))
         (wasm (make-instance 'wasm-resource :module "my-module")))
    (check ":fs tag"   (eq :fs   (car (serialize fs))))
    (check ":net tag"  (eq :net  (car (serialize net))))
    (check ":pid tag"  (eq :pid  (car (serialize pid))))
    (check ":ipc-fd tag" (eq :ipc-fd (car (serialize ipc))))
    (check ":http tag" (eq :http (car (serialize http))))
    (check ":wasm tag" (eq :wasm (car (serialize wasm))))
    (check "fs path preserved"
           (equal "/data/**" (getf (cdr (serialize fs)) :path)))
    (check "net host preserved"
           (equal "example.com" (getf (cdr (serialize net)) :host)))
    (check "net port-min preserved"
           (= 443 (getf (cdr (serialize net)) :port-min)))
    (check "pid ref preserved"
           (= 1234 (getf (cdr (serialize pid)) :ref)))
    (check "http url preserved"
           (equal "https://api.example.com/**"
                  (getf (cdr (serialize http)) :url)))
    (check "http methods preserved"
           (equal '(:get :post) (getf (cdr (serialize http)) :methods)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 2. Authority entry
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-serialize-authority-entry ()
  (let* ((entry (%fs-entry "/data/**" :read :write))
         (sexp  (serialize entry)))
    (check "entry tag is :entry" (eq :entry (car sexp)))
    (check "ops list present"
           (member :read (getf (cdr sexp) :ops)))
    (check "resource sub-sexp is tagged"
           (eq :fs (car (getf (cdr sexp) :resource))))))

(defun test-round-trip-authority-entry ()
  (let* ((entry  (%fs-entry "/data/reports/**" :read))
         (entry2 (round-trip entry)))
    (check "round-trip produces authority-entry"
           (typep entry2 'authority-entry))
    (check "round-trip preserves resource provider"
           (eq :linux-fs (resource-provider (entry-resource entry2))))
    (check "round-trip preserves path"
           (equal "/data/reports/**"
                  (path-glob-pattern (fs-resource-path (entry-resource entry2)))))
    (check "round-trip preserves ops"
           (op-set-subset-p (entry-ops entry2) (entry-ops entry)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 3. Delegation
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-delegation ()
  (let* ((entry (%fs-entry "/shared/**" :read))
         (del   (make-instance 'delegation
                               :grantor "root" :grantee "alice"
                               :authority (list entry)))
         (del2  (round-trip del)))
    (check "round-trip produces delegation"
           (typep del2 'delegation))
    (check "grantor preserved"
           (equal "root" (delegation-grantor del2)))
    (check "grantee preserved"
           (equal "alice" (delegation-grantee del2)))
    (check "authority list length preserved"
           (= 1 (length (delegation-authority del2))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 4. Effect
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-effect ()
  (let* ((eff  (make-fs-effect :write "/data/out.txt" "hello"))
         (eff2 (round-trip eff)))
    (check "round-trip produces effect"
           (typep eff2 'effect))
    (check "kind preserved"
           (eq :write (effect-kind eff2)))
    (check "resource-spec preserved"
           (equal "/data/out.txt" (effect-resource-spec eff2)))
    (check "payload preserved"
           (equal "hello" (effect-payload eff2)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 5. Delta
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-delta ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/report.csv")))
    (multiple-value-bind (delta _log)
        (with-saga "rt-delta-saga"
          (with-cap (list entry)
            (commit! effect)))
      (declare (ignore _log))
      (let ((delta2 (round-trip delta)))
        (check "round-trip produces delta"
               (delta-p delta2))
        (check "effect kind preserved"
               (eq (effect-kind (delta-effect delta))
                   (effect-kind (delta-effect delta2))))
        (check "effect resource-spec preserved"
               (equal (effect-resource-spec (delta-effect delta))
                      (effect-resource-spec (delta-effect delta2))))
        (check "epoch preserved"
               (= (delta-epoch delta) (delta-epoch delta2)))
        (check "saga-id preserved"
               (equal (delta-saga-id delta) (delta-saga-id delta2)))
        (check "sequence preserved"
               (= (delta-sequence delta) (delta-sequence delta2)))
        (check "timestamp preserved"
               (= (delta-timestamp delta) (delta-timestamp delta2)))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 6. Transfer receipt
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-transfer-receipt ()
  (let* ((entry (%fs-entry "/shared/**" :read)))
    (multiple-value-bind (receipt _log)
        (with-saga "rt-transfer-saga"
          (with-cap (list entry)
            (transfer! "alice" (list entry) :grantor-id "root")))
      (declare (ignore _log))
      (let ((receipt2 (round-trip receipt)))
        (check "round-trip produces transfer-receipt"
               (transfer-receipt-p receipt2))
        (check "saga-id preserved"
               (equal (transfer-receipt-saga-id receipt)
                      (transfer-receipt-saga-id receipt2)))
        (check "grantor preserved"
               (equal "root" (transfer-receipt-grantor receipt2)))
        (check "recipient preserved"
               (equal "alice" (transfer-receipt-recipient receipt2)))
        (check "sequence preserved"
               (= (transfer-receipt-sequence receipt)
                  (transfer-receipt-sequence receipt2)))
        (check "authority list length preserved"
               (= (length (transfer-receipt-authority receipt))
                  (length (transfer-receipt-authority receipt2))))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 7. Send receipt
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-send-receipt ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/x.txt")))
    (multiple-value-bind (receipt _log)
        (with-saga "rt-send-saga"
          (with-cap (list entry)
            (let ((d (commit! effect)))
              (send! "guardian" d :sender-id "shim"))))
      (declare (ignore _log))
      (let ((receipt2 (round-trip receipt)))
        (check "round-trip produces send-receipt"
               (send-receipt-p receipt2))
        (check "sender preserved"
               (equal "shim" (send-receipt-sender receipt2)))
        (check "recipient preserved"
               (equal "guardian" (send-receipt-recipient receipt2)))
        (check "message-kind preserved"
               (eq :delta (send-receipt-message-kind receipt2)))
        (check "sequence preserved"
               (= (send-receipt-sequence receipt)
                  (send-receipt-sequence receipt2)))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 8. Saga log
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-saga-log ()
  (let* ((entry   (%fs-entry "/data/**" :read :write))
         (effect1 (make-fs-effect :read  "/data/a.txt"))
         (effect2 (make-fs-effect :write "/data/b.txt")))
    (multiple-value-bind (_ log)
        (with-saga "rt-log-saga"
          (with-cap (list entry)
            (commit! effect1)
            (transfer! "bob" (list (%fs-entry "/data/**" :read)))
            (commit! effect2)))
      (declare (ignore _))
      (let ((log2 (round-trip log)))
        (check "round-trip produces saga-log"
               (saga-log-p log2))
        (check "saga-id preserved"
               (equal (saga-log-saga-id log) (saga-log-saga-id log2)))
        (check "entry count preserved"
               (= (length (saga-log-entries log))
                  (length (saga-log-entries log2))))
        (check "entry kinds preserved in order"
               (equal (mapcar #'saga-log-entry-kind (saga-log-entries log))
                      (mapcar #'saga-log-entry-kind (saga-log-entries log2))))
        (check "sequences preserved"
               (equal (mapcar #'saga-log-entry-sequence (saga-log-entries log))
                      (mapcar #'saga-log-entry-sequence (saga-log-entries log2))))
        (check "round-tripped log is consistent"
               (saga-log-consistent-p log2))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 9. Condition-set
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-round-trip-entry-with-conditions ()
  (let* ((cset  (make-instance 'condition-set :conditions '(:ttl 3600 :quorum 2)))
         (entry (make-instance 'authority-entry
                               :resource (make-instance 'fs-resource
                                                        :path (path-glob "/secure/**"))
                               :ops (op-set :read)
                               :conditions cset))
         (entry2 (round-trip entry)))
    (check "round-trip with conditions produces authority-entry"
           (typep entry2 'authority-entry))
    (check "conditions round-trip"
           (let ((c (entry-conditions entry2)))
             (and c
                  (= 3600 (getf (condition-set-conditions c) :ttl))
                  (= 2    (getf (condition-set-conditions c) :quorum)))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 10. Serialize-to-string is READ-able
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-serialize-to-string-is-readable ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (str    (serialize-to-string entry))
         (sexp   (read-from-string str)))
    (check "serialize-to-string returns a string"
           (stringp str))
    (check "string is READ-able back to a sexp"
           (consp sexp))
    (check "first element is :entry tag"
           (eq :entry (car sexp)))))

(defun test-nested-delegation-round-trip ()
  (let* ((parent-entry (%fs-entry "/data/**" :read :write))
         (child-entry  (%fs-entry "/data/sub/**" :read))
         (del1 (make-instance 'delegation
                              :grantor "root" :grantee "alice"
                              :authority (list parent-entry)))
         (del2 (make-instance 'delegation
                              :grantor "alice" :grantee "bob"
                              :authority (list child-entry)))
         (del1r (round-trip del1))
         (del2r (round-trip del2)))
    (check "two-hop grantor chain preserved"
           (and (equal "root"  (delegation-grantor del1r))
                (equal "alice" (delegation-grantee del1r))
                (equal "alice" (delegation-grantor del2r))
                (equal "bob"   (delegation-grantee del2r))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; RUNNER
;;; ══════════════════════════════════════════════════════════════════════════════

(defun run-serializer-tests ()
  (setq *pass* 0 *fail* 0)
  (format t "~&=== Serializer Tests ===~%")
  (test-serialize-resources)
  (test-round-trip-authority-entry)
  (test-round-trip-delegation)
  (test-round-trip-effect)
  (test-round-trip-delta)
  (test-round-trip-transfer-receipt)
  (test-round-trip-send-receipt)
  (test-round-trip-saga-log)
  (test-round-trip-entry-with-conditions)
  (test-serialize-to-string-is-readable)
  (test-nested-delegation-round-trip)
  (format t "~&~d passed, ~d failed.~%" *pass* *fail*)
  (zerop *fail*))
