(defpackage #:authority-dsl/tests/saga
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir
        #:authority-dsl/operational #:authority-dsl/saga))

(in-package #:authority-dsl/tests/saga)

;;; ── Test helpers ─────────────────────────────────────────────────────────────

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

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 1. WITH-SAGA: commit! log accumulation and sequence numbering
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-with-saga-records-commits ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/report.csv")))
    (multiple-value-bind (delta log)
        (with-saga "test-saga-1"
          (with-cap (list entry)
            (commit! effect)))
      (check "with-saga returns delta"
             (delta-p delta))
      (check "saga-log has one entry"
             (= 1 (length (saga-log-entries log))))
      (check "entry kind is :commit"
             (eq :commit (saga-log-entry-kind (first (saga-log-entries log)))))
      (check "entry payload is the delta"
             (eq delta (saga-log-entry-payload (first (saga-log-entries log)))))
      (check "saga-id embedded in delta"
             (equal "test-saga-1" (delta-saga-id delta)))
      (check "first delta has sequence 0 (pre-incf)"
             (= 0 (delta-sequence delta))))))

(defun test-with-saga-sequences-multiple-commits ()
  (let* ((entry   (%fs-entry "/data/**" :read :write))
         (effect1 (make-fs-effect :read  "/data/a.txt"))
         (effect2 (make-fs-effect :write "/data/b.txt")))
    (multiple-value-bind (result log)
        (with-saga "test-saga-seq"
          (with-cap (list entry)
            (let* ((d1 (commit! effect1))
                   (d2 (commit! effect2)))
              (list d1 d2))))
      (check "two entries in log"
             (= 2 (length (saga-log-entries log))))
      (check "first delta sequence = 0"
             (= 0 (delta-sequence (first result))))
      (check "second delta sequence = 1"
             (= 1 (delta-sequence (second result))))
      (check "log is consistent"
             (saga-log-consistent-p log)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 2. TRANSFER!: authority transfer with saga log recording
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-transfer-records-in-saga-log ()
  (let* ((entry (%fs-entry "/shared/**" :read)))
    (multiple-value-bind (receipt log)
        (with-saga "test-saga-transfer"
          (with-cap (list entry)
            (transfer! "alice" (list entry) :grantor-id "root")))
      (check "transfer! returns transfer-receipt"
             (transfer-receipt-p receipt))
      (check "recipient is alice"
             (equal "alice" (transfer-receipt-recipient receipt)))
      (check "grantor is root"
             (equal "root" (transfer-receipt-grantor receipt)))
      (check "saga-log has one :transfer entry"
             (and (= 1 (length (saga-log-entries log)))
                  (eq :transfer (saga-log-entry-kind (first (saga-log-entries log))))))
      (check "entry payload is the receipt"
             (eq receipt (saga-log-entry-payload (first (saga-log-entries log))))))))

(defun test-transfer-after-commit-sequences-correctly ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/x.txt")))
    (multiple-value-bind (_ log)
        (with-saga "test-saga-seq2"
          (with-cap (list entry)
            (commit! effect)               ; sequence 0
            (transfer! "bob" (list entry)))) ; sequence 1
      (declare (ignore _))
      (check "log has 2 entries"
             (= 2 (length (saga-log-entries log))))
      (check "log is consistent (0, 1)"
             (saga-log-consistent-p log))
      (check "transfer entry has sequence 1"
             (= 1 (saga-log-entry-sequence (second (saga-log-entries log))))))))

(defun test-transfer-without-authority-signals-error ()
  (let* ((broad  (%fs-entry "/data/**" :read))
         (narrow (%fs-entry "/secret/**" :read))
         (errored nil))
    (multiple-value-bind (_ _log)
        (with-saga "test-saga-noauth"
          (with-cap (list broad)
            (handler-case
                (transfer! "eve" (list narrow))
              (capability-error ()
                (setq errored t)))))
      (declare (ignore _ _log)))
    (check "transfer! without covering authority signals capability-error"
           errored)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 3. SEND!: message send recording
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-send-records-in-saga-log ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/report.txt")))
    (multiple-value-bind (receipt log)
        (with-saga "test-saga-send"
          (with-cap (list entry)
            (let ((d (commit! effect)))
              (send! "guardian" d :sender-id "shim"))))
      (check "send! returns send-receipt"
             (send-receipt-p receipt))
      (check "message kind is :delta"
             (eq :delta (send-receipt-message-kind receipt)))
      (check "recipient is guardian"
             (equal "guardian" (send-receipt-recipient receipt)))
      (check "log has 2 entries: :commit then :send"
             (= 2 (length (saga-log-entries log))))
      (let ((es (saga-log-entries log)))
        (check "first entry is :commit"
               (eq :commit (saga-log-entry-kind (first es))))
        (check "second entry is :send"
               (eq :send   (saga-log-entry-kind (second es))))))))

(defun test-send-transfer-receipt-kind ()
  (let* ((entry (%fs-entry "/tmp/**" :write)))
    (multiple-value-bind (receipt _log)
        (with-saga "test-saga-send-tr"
          (with-cap (list entry)
            (let ((tr (transfer! "bob" (list entry))))
              (send! "charlie" tr))))
      (declare (ignore _log))
      (check "send of transfer-receipt has kind :transfer-receipt"
             (eq :transfer-receipt (send-receipt-message-kind receipt))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 4. JUSTIFIED-P: two-proof invariant
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-justified-p-true-for-valid-commit ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/report.csv")))
    (multiple-value-bind (delta log)
        (with-saga "test-justified-1"
          (with-cap (list entry)
            (commit! effect)))
      (check "delta is justified against its saga-log"
             (justified-p delta log)))))

(defun test-justified-p-false-for-wrong-log ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/file.txt")))
    (multiple-value-bind (delta _log)
        (with-saga "test-justified-2a"
          (with-cap (list entry)
            (commit! effect)))
      (declare (ignore _log))
      (multiple-value-bind (_ other-log)
          (with-saga "test-justified-2b"
            (with-cap (list entry)
              (commit! (make-fs-effect :read "/data/other.txt"))))
        (declare (ignore _))
        (check "delta NOT justified against a different saga's log"
               (not (justified-p delta other-log)))))))

(defun test-justified-p-false-for-fabricated-delta ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/x.txt"))
         ;; Fabricate a delta outside any saga context.
         (fake   (let ((*current-saga-id* "forged")
                       (*current-saga-sequence* 0))
                   (make-delta effect entry 0))))
    (multiple-value-bind (_ real-log)
        (with-saga "test-justified-3"
          (with-cap (list entry)
            (commit! (make-fs-effect :read "/data/legit.txt"))))
      (declare (ignore _))
      (check "fabricated delta not justified against unrelated log"
             (not (justified-p fake real-log))))))

(defun test-saga-log-consistent-p ()
  (let* ((entry   (%fs-entry "/data/**" :read))
         (effect1 (make-fs-effect :read "/data/a.txt"))
         (effect2 (make-fs-effect :read "/data/b.txt"))
         (effect3 (make-fs-effect :read "/data/c.txt")))
    (multiple-value-bind (_ log)
        (with-saga "test-consistent"
          (with-cap (list entry)
            (commit! effect1)
            (commit! effect2)
            (commit! effect3)))
      (declare (ignore _))
      (check "three-commit log is consistent"
             (saga-log-consistent-p log))
      (check "last sequence is 2"
             (= 2 (saga-log-last-sequence log))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 5. MERGE-SAGA-LOGS: deterministic total order across sessions
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-merge-saga-logs-deterministic ()
  (let* ((entry-a  (%fs-entry "/a/**" :read))
         (entry-b  (%fs-entry "/b/**" :read))
         (effect-a (make-fs-effect :read "/a/file1.txt"))
         (effect-b (make-fs-effect :read "/b/file1.txt")))
    (multiple-value-bind (_ log-a)
        (with-saga "saga-a"
          (let ((*current-epoch* 1))
            (with-cap (list entry-a)
              (commit! effect-a))))
      (declare (ignore _))
      (multiple-value-bind (_ log-b)
          (with-saga "saga-b"
            (let ((*current-epoch* 2))
              (with-cap (list entry-b)
                (commit! effect-b))))
        (declare (ignore _))
        (let* ((merged1 (merge-saga-logs log-a log-b))
               (merged2 (merge-saga-logs log-b log-a))  ; reversed input
               (epoch-of (lambda (e) (delta-epoch (saga-log-entry-payload e)))))
          (check "merged log has 2 entries"
                 (= 2 (length merged1)))
          (check "epoch-1 entry comes first"
                 (= 1 (funcall epoch-of (first merged1))))
          (check "epoch-2 entry comes second"
                 (= 2 (funcall epoch-of (second merged1))))
          (check "merge is order-independent"
                 (equal (mapcar (lambda (e)
                                  (list (saga-log-entry-sequence e)
                                        (delta-saga-id (saga-log-entry-payload e))))
                                merged1)
                        (mapcar (lambda (e)
                                  (list (saga-log-entry-sequence e)
                                        (delta-saga-id (saga-log-entry-payload e))))
                                merged2))))))))

(defun test-merge-saga-logs-interleaved-transfers ()
  (let* ((entry  (%fs-entry "/shared/**" :read)))
    (multiple-value-bind (_ log-a)
        (with-saga "session-a"
          (let ((*current-epoch* 1))
            (with-cap (list entry)
              (commit! (make-fs-effect :read "/shared/a.txt"))  ; seq 0
              (transfer! "bob" (list entry)))))                  ; seq 1
      (declare (ignore _))
      (multiple-value-bind (_ log-b)
          (with-saga "session-b"
            (let ((*current-epoch* 1))
              (with-cap (list entry)
                (commit! (make-fs-effect :read "/shared/b.txt")))))
        (declare (ignore _))
        (let ((merged (merge-saga-logs log-a log-b)))
          (check "merged has 3 entries (2 commit + 1 transfer)"
                 (= 3 (length merged)))
          (check "all three kinds present"
                 (and (member :commit   (mapcar #'saga-log-entry-kind merged))
                      (member :transfer (mapcar #'saga-log-entry-kind merged)))))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 6. REFLECTOR: cross-session observation
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-reflector-observe-committed-state ()
  (let* ((entry  (%fs-entry "/shared/**" :write))
         (effect (make-fs-effect :write "/shared/config.json")))
    (multiple-value-bind (delta log)
        (with-saga "alice-saga"
          (with-cap (list entry)
            (commit! effect)))
      (let ((r (make-reflector)))
        (reflector-submit r log)
        (multiple-value-bind (status rspec observed)
            (reflector-observe r "/shared/config.json")
          (check "reflector-observe returns :observed"
                 (eq :observed status))
          (check "observed resource-spec matches"
                 (equal "/shared/config.json" rspec))
          (check "observed delta is the committed delta"
                 (eq delta observed)))))))

(defun test-reflector-observe-not-found ()
  (let* ((entry  (%fs-entry "/data/**" :read))
         (effect (make-fs-effect :read "/data/report.txt")))
    (multiple-value-bind (_ log)
        (with-saga "bob-saga"
          (with-cap (list entry)
            (commit! effect)))
      (declare (ignore _))
      (let ((r (make-reflector)))
        (reflector-submit r log)
        (multiple-value-bind (status rspec observed)
            (reflector-observe r "/data/nonexistent.txt")
          (check "reflector-observe returns :not-found for absent resource"
                 (eq :not-found status))
          (check "resource-spec echoed back"
                 (equal "/data/nonexistent.txt" rspec))
          (check "observed delta is nil"
                 (null observed)))))))

(defun test-reflector-cross-session-latest-epoch-wins ()
  (let* ((entry   (%fs-entry "/state/**" :write))
         (effect1 (make-fs-effect :write "/state/counter"))
         (effect2 (make-fs-effect :write "/state/counter")))
    (multiple-value-bind (_ log-a)
        (with-saga "session-a"
          (let ((*current-epoch* 1))
            (with-cap (list entry)
              (commit! effect1))))
      (declare (ignore _))
      (multiple-value-bind (d2 log-b)
          (with-saga "session-b"
            (let ((*current-epoch* 2))
              (with-cap (list entry)
                (commit! effect2))))
        (let ((r (make-reflector)))
          (reflector-submit r log-a)
          (reflector-submit r log-b)
          (multiple-value-bind (status _ observed)
              (reflector-observe r "/state/counter")
            (declare (ignore _))
            (check "reflector-observe returns :observed"
                   (eq :observed status))
            (check "latest epoch (2) delta is returned"
                   (= 2 (delta-epoch observed)))
            (check "observed delta is d2"
                   (eq d2 observed))))))))

(defun test-reflector-submit-replaces-same-saga ()
  (let* ((entry   (%fs-entry "/data/**" :read))
         (effect1 (make-fs-effect :read "/data/v1.txt"))
         (effect2 (make-fs-effect :read "/data/v2.txt")))
    (multiple-value-bind (_ log-v1)
        (with-saga "my-saga"
          (with-cap (list entry)
            (commit! effect1)))
      (declare (ignore _))
      (multiple-value-bind (d2 log-v2)
          (with-saga "my-saga"
            (with-cap (list entry)
              (commit! effect2)))
        (let ((r (make-reflector)))
          (reflector-submit r log-v1)
          (reflector-submit r log-v2)  ; replaces log-v1 for same saga-id
          (check "reflector global has 1 entry after replacement"
                 (= 1 (length (reflector-global-log r))))
          (check "the surviving entry is from log-v2"
                 (eq d2 (saga-log-entry-payload
                         (first (reflector-global-log r))))))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 7. THREE-WAY SEPARATION: delegate / transfer! / send! are distinct
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-delegate-vs-transfer-vs-send ()
  (let* ((parent-entry (%fs-entry "/data/**" :read))
         (child-entry  (%fs-entry "/data/subdir/**" :read))
         ;; delegate: pure DSL description, produces a delegation object
         (del (make-instance 'delegation
                             :grantor   "root"
                             :grantee   "alice"
                             :authority (list parent-entry))))
    (check "delegate produces a delegation (not a receipt)"
           (typep del 'delegation))
    ;; transfer!: runtime, linear state change with operational evidence
    (multiple-value-bind (tr-receipt log)
        (with-saga "three-way-saga"
          (with-cap (list parent-entry)
            (transfer! "alice" (list child-entry) :grantor-id "root")))
      (check "transfer! produces a transfer-receipt"
             (transfer-receipt-p tr-receipt))
      (check "transfer appears in saga-log"
             (some (lambda (e) (eq :transfer (saga-log-entry-kind e)))
                   (saga-log-entries log)))
      ;; send!: actor communication, no authority check
      (multiple-value-bind (sr _)
          (with-saga "send-saga"
            (send! "guardian" tr-receipt))
        (declare (ignore _))
        (check "send! produces a send-receipt"
               (send-receipt-p sr))
        (check "send message-kind is :transfer-receipt"
               (eq :transfer-receipt (send-receipt-message-kind sr)))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 8. OUTSIDE SAGA CONTEXT: transfer! and send! work without a saga
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-transfer-outside-saga ()
  (let* ((entry (%fs-entry "/tmp/**" :write)))
    (with-cap (list entry)
      (let ((receipt (transfer! "bob" (list entry))))
        (check "transfer! outside saga returns a receipt"
               (transfer-receipt-p receipt))
        (check "saga-id is nil outside saga"
               (null (transfer-receipt-saga-id receipt)))
        (check "sequence is 0 outside saga"
               (= 0 (transfer-receipt-sequence receipt)))))))

(defun test-send-outside-saga ()
  (let ((receipt (send! "guardian" :opaque-value)))
    (check "send! outside saga returns a receipt"
           (send-receipt-p receipt))
    (check "message-kind is :value for untyped data"
           (eq :value (send-receipt-message-kind receipt)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; RUNNER
;;; ══════════════════════════════════════════════════════════════════════════════

(defun run-saga-tests ()
  (setq *pass* 0 *fail* 0)
  (format t "~&=== Saga Tests ===~%")
  (test-with-saga-records-commits)
  (test-with-saga-sequences-multiple-commits)
  (test-transfer-records-in-saga-log)
  (test-transfer-after-commit-sequences-correctly)
  (test-transfer-without-authority-signals-error)
  (test-send-records-in-saga-log)
  (test-send-transfer-receipt-kind)
  (test-justified-p-true-for-valid-commit)
  (test-justified-p-false-for-wrong-log)
  (test-justified-p-false-for-fabricated-delta)
  (test-saga-log-consistent-p)
  (test-merge-saga-logs-deterministic)
  (test-merge-saga-logs-interleaved-transfers)
  (test-reflector-observe-committed-state)
  (test-reflector-observe-not-found)
  (test-reflector-cross-session-latest-epoch-wins)
  (test-reflector-submit-replaces-same-saga)
  (test-delegate-vs-transfer-vs-send)
  (test-transfer-outside-saga)
  (test-send-outside-saga)
  (format t "~&~d passed, ~d failed.~%" *pass* *fail*)
  (zerop *fail*))
