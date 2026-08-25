(defpackage #:authority-dsl/saga
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir
        #:authority-dsl/verifier #:authority-dsl/operational)
  (:export
   ;; Saga log
   #:saga-log #:saga-log-p #:make-saga-log
   #:saga-log-saga-id #:saga-log-entries #:saga-log-sequence
   ;; Saga log entry
   #:saga-log-entry #:saga-log-entry-kind #:saga-log-entry-sequence
   #:saga-log-entry-payload #:saga-log-entry-timestamp
   ;; Transfer
   #:transfer-receipt #:transfer-receipt-p
   #:transfer-receipt-saga-id #:transfer-receipt-sequence
   #:transfer-receipt-grantor #:transfer-receipt-recipient
   #:transfer-receipt-authority #:transfer-receipt-timestamp
   #:transfer!
   ;; Send
   #:send-receipt #:send-receipt-p
   #:send-receipt-saga-id #:send-receipt-sequence
   #:send-receipt-sender #:send-receipt-recipient
   #:send-receipt-message-kind #:send-receipt-timestamp
   #:send!
   ;; Saga context macro
   #:with-saga
   ;; Invariant predicates
   #:justified-p #:saga-log-consistent-p
   #:saga-log-contains-p #:saga-log-last-sequence
   ;; Reflector
   #:reflector #:reflector-p #:make-reflector
   #:reflector-submit #:reflector-observe #:reflector-global-log
   ;; Multi-log merge
   #:merge-saga-logs
   ;; Serializer support — public construction wrappers for internal structs
   #:make-transfer-receipt-from-parts
   #:make-send-receipt-from-parts
   #:make-saga-log-entry-from-parts
   #:saga-log-push-entry!))

(in-package #:authority-dsl/saga)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; HOOK VARIABLES
;;;
;;; saga.lisp is the only package that sets these.  They must be defvar'd before
;;; transfer! and send! reference them.  *saga-commit-hook* lives in operational
;;; because commit! is defined there; the transfer and send hooks live here.
;;; ══════════════════════════════════════════════════════════════════════════════

(defvar *saga-transfer-hook* nil
  "Called (transfer-receipt) after every successful TRANSFER!.
   Bound by WITH-SAGA; nil outside a saga context.")

(defvar *saga-send-hook* nil
  "Called (send-receipt) after every successful SEND!.
   Bound by WITH-SAGA; nil outside a saga context.")

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SAGA LOG TYPES
;;;
;;; A saga-log records every operation in the saga in order.  The entries list
;;; is stored most-recent-first internally; SAGA-LOG-ENTRIES returns chronological
;;; order.  The log is the operational derivation for the justified-p invariant.
;;; ══════════════════════════════════════════════════════════════════════════════

(defstruct (saga-log-entry (:constructor %make-saga-log-entry))
  (kind     nil :type symbol)  ; :commit | :transfer | :send
  (sequence 0   :type integer)
  payload                      ; delta, transfer-receipt, or send-receipt
  (timestamp 0  :type integer))

(defstruct (saga-log (:constructor %make-saga-log))
  saga-id
  (entries% nil)   ; internal: most-recent-first list of saga-log-entry
  (sequence  0))   ; high-water mark (last recorded sequence number)

(defun make-saga-log (saga-id)
  (%make-saga-log :saga-id saga-id))

(defun saga-log-entries (log)
  "Return entries in chronological (ascending sequence) order."
  (reverse (saga-log-entries% log)))

(defun %saga-log-push! (log entry)
  "Append ENTRY to LOG (mutates LOG in place)."
  (push entry (saga-log-entries% log))
  (setf (saga-log-sequence log) (saga-log-entry-sequence entry))
  log)

;;; ── Transfer receipt ─────────────────────────────────────────────────────────
;;; Records that a principal transferred capability to a named recipient.
;;; The transfer-receipt is evidence that the linear ownership state changed at
;;; a specific saga position.

(defstruct (transfer-receipt (:constructor %make-transfer-receipt))
  saga-id
  (sequence 0 :type integer)
  grantor    ; string principal-id
  recipient  ; string principal-id
  authority  ; list of authority-entry being transferred
  (timestamp 0 :type integer))

;;; ── Send receipt ─────────────────────────────────────────────────────────────
;;; Records that a message was sent to an actor.  No authority re-check here —
;;; authority was verified at commit! or transfer! time.

(defstruct (send-receipt (:constructor %make-send-receipt))
  saga-id
  (sequence 0 :type integer)
  sender
  recipient
  message-kind   ; :delta | :transfer-receipt | :capability | :value
  (timestamp 0 :type integer))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; WITH-SAGA
;;;
;;; Establishes a saga context.  Binds all three hook variables and the saga-id /
;;; sequence counters from operational.  Returns (values body-result saga-log).
;;;
;;; Sequence numbering: every operation (commit!, transfer!, send!) captures the
;;; current *current-saga-sequence* value as its sequence number, then increments.
;;; This matches the pre-incf convention already in operational's %do-commit!.
;;; Result: the first commit in a saga has sequence 0, the next operation has 1,
;;; and so on — a gapless total order over all saga entries.
;;; ══════════════════════════════════════════════════════════════════════════════

(defmacro with-saga (saga-id &body body)
  "Run BODY inside a saga context identified by SAGA-ID.
   All COMMIT!, TRANSFER!, and SEND! calls within BODY are recorded in a new
   SAGA-LOG.  Returns (values result saga-log)."
  (let ((log-sym (gensym "saga-log-")))
    `(let* ((,log-sym              (make-saga-log ,saga-id))
            (*current-saga-id*     ,saga-id)
            (*current-saga-sequence* 0)
            ;; Commit hook: record deltas from operational's commit!.
            (*saga-commit-hook*
             (lambda (delta)
               (%saga-log-push! ,log-sym
                                (%make-saga-log-entry
                                 :kind      :commit
                                 :sequence  (delta-sequence delta)
                                 :payload   delta
                                 :timestamp (get-universal-time)))))
            ;; Transfer hook: record receipts from transfer!.
            (*saga-transfer-hook*
             (lambda (receipt)
               (%saga-log-push! ,log-sym
                                (%make-saga-log-entry
                                 :kind      :transfer
                                 :sequence  (transfer-receipt-sequence receipt)
                                 :payload   receipt
                                 :timestamp (get-universal-time)))))
            ;; Send hook: record receipts from send!.
            (*saga-send-hook*
             (lambda (receipt)
               (%saga-log-push! ,log-sym
                                (%make-saga-log-entry
                                 :kind      :send
                                 :sequence  (send-receipt-sequence receipt)
                                 :payload   receipt
                                 :timestamp (get-universal-time))))))
       (let ((result (progn ,@body)))
         (values result ,log-sym)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; TRANSFER!
;;;
;;; Operational state change — "I am delegating this capability to RECIPIENT."
;;; Semantics differ from (cap delegate ...):
;;;   delegate  — pure description; produces a delegation edge for verification
;;;   transfer! — runtime; linear state change with operational evidence
;;;
;;; Authority check: every entry in AUTHORITY-TO-TRANSFER must be covered by the
;;; current capability scope (same predicate as commit!).
;;;
;;; After transfer! the reflector treats the authority as owned by RECIPIENT.
;;; Double-use by the original grantor is detectable via SAGA-LOG-CONSISTENT-P.
;;; ══════════════════════════════════════════════════════════════════════════════

(defun transfer! (recipient-id authority-to-transfer &key grantor-id)
  "Transfer AUTHORITY-TO-TRANSFER to RECIPIENT-ID within the current saga.
   AUTHORITY-TO-TRANSFER is an AUTHORITY-ENTRY or a list thereof.
   Returns a TRANSFER-RECEIPT and records the transfer in the current saga-log."
  (let ((entries (if (listp authority-to-transfer)
                     authority-to-transfer
                     (list authority-to-transfer))))
    ;; Authority check: every entry being transferred must be in scope.
    (dolist (e entries)
      (unless (scope-covers-p e *current-caps*)
        (let ((rspec (resource-canonical-string (entry-resource e))))
          (error 'capability-error
                 :effect  (make-instance 'effect :kind :transfer :resource-spec rspec)
                 :message (format nil "transfer! authority not in scope: ~a" rspec)))))
    ;; Capture pre-incf sequence (same convention as %do-commit! in operational).
    (let* ((seq     *current-saga-sequence*)
           (receipt (%make-transfer-receipt
                     :saga-id   *current-saga-id*
                     :sequence  seq
                     :grantor   (or grantor-id "unknown")
                     :recipient recipient-id
                     :authority entries
                     :timestamp (get-universal-time))))
      (when *current-saga-id*
        (incf *current-saga-sequence*))
      (when *saga-transfer-hook*
        (funcall *saga-transfer-hook* receipt))
      receipt)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SEND!
;;;
;;; Delivers a message to a named actor.  No authority check — the authority was
;;; verified at the commit! or transfer! that produced the message.
;;; Records in the saga-log so the reflector can route and order the message.
;;; ══════════════════════════════════════════════════════════════════════════════

(defun send! (recipient-id message &key sender-id)
  "Send MESSAGE to RECIPIENT-ID within the current saga.
   Returns a SEND-RECEIPT and records the send in the current saga-log."
  (let* ((kind    (etypecase message
                    (delta            :delta)
                    (transfer-receipt :transfer-receipt)
                    (authority-entry  :capability)
                    (capability       :capability)
                    (list             :value)
                    (t                :value)))
         (seq     *current-saga-sequence*)
         (receipt (%make-send-receipt
                   :saga-id      *current-saga-id*
                   :sequence     seq
                   :sender       (or sender-id "unknown")
                   :recipient    recipient-id
                   :message-kind kind
                   :timestamp    (get-universal-time))))
    (when *current-saga-id*
      (incf *current-saga-sequence*))
    (when *saga-send-hook*
      (funcall *saga-send-hook* receipt))
    receipt))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; INVARIANT PREDICATES
;;;
;;; The key invariant: every committed effect is justified by BOTH:
;;;   1. An authority derivation  — delta-authority is non-nil (checked by commit!)
;;;   2. An operational derivation — the delta appears in a consistent saga-log
;;;
;;; Without (2), a delta is a unilateral claim that may be fabricated.
;;; With (2), the saga-log proves the effect was properly sequenced.
;;; ══════════════════════════════════════════════════════════════════════════════

(defun saga-log-contains-p (log delta)
  "True iff DELTA appears as a :commit entry in LOG."
  (some (lambda (e)
          (and (eq :commit (saga-log-entry-kind e))
               (eq delta   (saga-log-entry-payload e))))
        (saga-log-entries% log)))

(defun saga-log-last-sequence (log)
  "Return the sequence number of the most recent entry, or -1 if empty."
  (if (null (saga-log-entries% log))
      -1
      (saga-log-entry-sequence (first (saga-log-entries% log)))))

(defun saga-log-consistent-p (log)
  "True iff LOG has no gaps: entries have sequences 0, 1, 2, …, n.
   A gap indicates a fabricated or dropped entry."
  (loop for e in (saga-log-entries log)  ; chronological, ascending sequence
        for expected from 0
        always (= expected (saga-log-entry-sequence e))))

(defun justified-p (delta saga-log)
  "True iff DELTA satisfies both the authority derivation and operational
   derivation halves of the justified-effect invariant:
     1. delta-authority is non-nil  (authority was verified at commit! time)
     2. the delta appears in SAGA-LOG as a :commit entry
     3. the saga-log has no gaps   (no fabricated or dropped entries)
     4. the delta's saga-id matches the log's saga-id"
  (and (not (null (delta-authority delta)))
       (equal (delta-saga-id delta) (saga-log-saga-id saga-log))
       (saga-log-contains-p saga-log delta)
       (saga-log-consistent-p saga-log)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; MERGE-SAGA-LOGS
;;;
;;; Given saga-logs from multiple sessions, produce a single deterministically-
;;; ordered list of saga-log-entry representing the global total order.
;;;
;;; Total order key (lexicographic):
;;;   1. Epoch of the entry's payload (commits carry epoch; transfers/sends get 0)
;;;   2. Timestamp
;;;   3. Saga-id string (breaks timestamp ties deterministically)
;;;   4. Sequence within saga (preserves each log's internal causal order)
;;;
;;; This order respects each session's internal causal order while giving a
;;; consistent global view that the reflector uses for cross-session observe.
;;; ══════════════════════════════════════════════════════════════════════════════

(defun merge-saga-logs (&rest logs)
  "Merge LOGS into a single deterministically-ordered list of SAGA-LOG-ENTRY."
  (let ((all (loop for log in logs
                   nconc (copy-list (saga-log-entries log)))))
    (stable-sort all #'%entry<)))

(defun %entry< (a b)
  "Total order predicate for saga-log entries."
  (let ((ea (%entry-epoch a))
        (eb (%entry-epoch b)))
    (cond ((< ea eb) t)
          ((> ea eb) nil)
          ((< (saga-log-entry-timestamp a) (saga-log-entry-timestamp b)) t)
          ((> (saga-log-entry-timestamp a) (saga-log-entry-timestamp b)) nil)
          (t (let ((sa (or (%entry-saga-id a) ""))
                   (sb (or (%entry-saga-id b) "")))
               (if (string/= sa sb)
                   (string< sa sb)
                   (< (saga-log-entry-sequence a)
                      (saga-log-entry-sequence b))))))))

(defun %entry-epoch (entry)
  (let ((p (saga-log-entry-payload entry)))
    (etypecase p
      (delta            (delta-epoch p))
      (transfer-receipt 0)
      (send-receipt     0))))

(defun %entry-saga-id (entry)
  (let ((p (saga-log-entry-payload entry)))
    (etypecase p
      (delta            (delta-saga-id p))
      (transfer-receipt (transfer-receipt-saga-id p))
      (send-receipt     (send-receipt-saga-id p)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; REFLECTOR
;;;
;;; Maintains a consistent global view across all submitted saga-logs.
;;; Enables cross-session observation: Alice commits in her saga; Bob calls
;;; (reflector-observe r "/alice/data") and gets Alice's last committed delta.
;;;
;;; The reflector does NOT re-verify authority — that was verified at commit!
;;; time.  It verifies only operational consistency: effects appear in a
;;; deterministic total order with no duplicates.
;;; ══════════════════════════════════════════════════════════════════════════════

(defstruct (reflector (:constructor %make-reflector))
  (logs   (make-hash-table :test #'equal))  ; saga-id → saga-log
  (global nil))                             ; sorted list of saga-log-entry

(defun make-reflector ()
  (%make-reflector))

(defun reflector-submit (reflector saga-log)
  "Submit SAGA-LOG to REFLECTOR, merging it into the global total order.
   Replaces any previously submitted log for the same saga-id.
   Returns REFLECTOR."
  (setf (gethash (saga-log-saga-id saga-log) (reflector-logs reflector))
        saga-log)
  (%recompute-global reflector)
  reflector)

(defun reflector-global-log (reflector)
  "Return the global merged list of SAGA-LOG-ENTRY in total order."
  (reflector-global reflector))

(defun %recompute-global (reflector)
  (setf (reflector-global reflector)
        (apply #'merge-saga-logs
               (loop for v being the hash-values of (reflector-logs reflector)
                     collect v))))

(defun reflector-observe (reflector resource-spec)
  "Return the most recently committed delta for RESOURCE-SPEC across all sessions
   known to REFLECTOR.  'Most recent' is the last entry in the global total order
   whose effect's resource-spec matches.
   Returns (values :observed resource-spec delta) or (values :not-found resource-spec nil)."
  (let ((matching
         (remove-if-not
          (lambda (e)
            (and (eq :commit (saga-log-entry-kind e))
                 (equal (effect-resource-spec
                         (delta-effect (saga-log-entry-payload e)))
                        resource-spec)))
          (reflector-global reflector))))
    (if matching
        (values :observed resource-spec
                (saga-log-entry-payload (car (last matching))))
        (values :not-found resource-spec nil))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SERIALIZER SUPPORT
;;;
;;; Public construction wrappers around the internal %make-* constructors.
;;; These are the only stable entry points for external packages (serializer,
;;; tests) that need to reconstruct saga objects from deserialized data.
;;; ══════════════════════════════════════════════════════════════════════════════

(defun make-transfer-receipt-from-parts (&key saga-id sequence grantor recipient authority timestamp)
  (%make-transfer-receipt :saga-id   saga-id
                          :sequence  (or sequence 0)
                          :grantor   grantor
                          :recipient recipient
                          :authority (or authority nil)
                          :timestamp (or timestamp 0)))

(defun make-send-receipt-from-parts (&key saga-id sequence sender recipient message-kind timestamp)
  (%make-send-receipt :saga-id      saga-id
                      :sequence     (or sequence 0)
                      :sender       sender
                      :recipient    recipient
                      :message-kind message-kind
                      :timestamp    (or timestamp 0)))

(defun make-saga-log-entry-from-parts (&key kind sequence payload timestamp)
  (%make-saga-log-entry :kind      kind
                        :sequence  (or sequence 0)
                        :payload   payload
                        :timestamp (or timestamp 0)))

(defun saga-log-push-entry! (log entry)
  "Append ENTRY (a SAGA-LOG-ENTRY) to LOG in chronological order.
   Intended for use by the serializer when rebuilding a log from wire data."
  (%saga-log-push! log entry))
