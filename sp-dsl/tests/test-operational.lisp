(defpackage #:authority-dsl/tests/operational
  (:use #:cl
        #:authority-dsl/algebra
        #:authority-dsl/ir
        #:authority-dsl/parser
        #:authority-dsl/verifier
        #:authority-dsl/operational))

(in-package #:authority-dsl/tests/operational)

(defvar *pass* 0)
(defvar *fail* 0)

(defmacro check (label form)
  `(if ,form
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a~%" ,label))))

(defmacro check-error (label condition-type &body body)
  `(if (handler-case (progn ,@body nil)
         (,condition-type () t)
         (error () nil))
       (progn (incf *pass*) (format t "  PASS  ~a~%" ,label))
       (progn (incf *fail*) (format t "  FAIL  ~a (wrong or no error)~%" ,label))))

;;; ── Shared fixtures ──────────────────────────────────────────────────────────

(defun data-read-entry ()
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource :path (path-glob "/data/**"))
                 :ops (op-set :read)))

(defun data-write-entry ()
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource :path (path-glob "/data/**"))
                 :ops (op-set :write)))

(defun session-entry ()
  (make-instance 'authority-entry
                 :resource (make-instance 'fs-resource :path (path-glob "/data/session/**"))
                 :ops (op-set :read :write)))

(defun api-entry ()
  (make-instance 'authority-entry
                 :resource (make-instance 'http-resource
                                          :url-pattern "https://api.example.com/v1/**"
                                          :methods (op-set :get))
                 :ops (op-set :get)))

(defun pid-entry (ref)
  (make-instance 'authority-entry
                 :resource (make-instance 'pid-resource :ref ref)
                 :ops (op-set :signal)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 1. with-cap SCOPING
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-with-cap-scope ()
  (format t "~%── with-cap lexical scope ──~%")

  ;; Inside with-cap, the authority is in scope.
  (check "commit! succeeds inside with-cap"
         (with-cap (data-write-entry)
           (let ((d (commit! (make-fs-effect :write "/data/session.json" "content"))))
             (delta-p d))))

  ;; Outside with-cap, authority is gone.
  (check "commit! fails outside with-cap"
         (handler-case
             (progn
               (commit! (make-fs-effect :write "/data/session.json" "content"))
               nil)
           (capability-error () t)))

  ;; Nested with-cap: inner scope has union of authorities.
  (check "nested with-cap accumulates authority"
         (with-cap (data-read-entry)
           (with-cap (data-write-entry)
             (and
              ;; read is in scope from outer
              (scope-covers-p (make-instance 'authority-entry
                                            :resource (make-instance 'fs-resource
                                                                     :path (path-glob "/data/a/**"))
                                            :ops (op-set :read))
                              *current-caps*)
              ;; write is in scope from inner
              (scope-covers-p (make-instance 'authority-entry
                                            :resource (make-instance 'fs-resource
                                                                     :path (path-glob "/data/b/**"))
                                            :ops (op-set :write))
                              *current-caps*)))))

  ;; with-cap with a parsed capability object.
  (let ((cap (parse-capability '(cap delegate
                                  (subject worker-17)
                                  (authority (fs (write "/data/**")))))))
    (check "with-cap accepts parsed capability"
           (with-cap cap
             (delta-p (commit! (make-fs-effect :write "/data/out.json" "x"))))))

  ;; with-cap with a session.
  (let ((sess (make-session "alice" (list (data-read-entry)) 5)))
    (check "with-cap accepts session"
           (with-cap sess
             (multiple-value-bind (tag _)
                 (observe "/data/alice.json")
               (declare (ignore _))
               (eq :observed tag))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 2. commit! PRODUCES CORRECT DELTA
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-commit-delta ()
  (format t "~%── commit! delta structure ──~%")

  (let* ((auth  (data-write-entry))
         (delta (with-cap auth
                  (commit! (make-fs-effect :write "/data/out.json" "hello")
                           :before "sha256-before"
                           :after  "sha256-after"))))
    (check "delta is a delta struct"
           (delta-p delta))
    (check "delta effect kind is :write"
           (eq :write (effect-kind (delta-effect delta))))
    (check "delta effect resource is the path"
           (string= "/data/out.json" (effect-resource-spec (delta-effect delta))))
    (check "delta effect payload is content"
           (string= "hello" (effect-payload (delta-effect delta))))
    (check "delta authority is the covering entry"
           (not (null (delta-authority delta))))
    (check "delta epoch matches *current-epoch*"
           (= *current-epoch* (delta-epoch delta)))
    (check "delta before-state recorded"
           (string= "sha256-before" (delta-before delta)))
    (check "delta after-state recorded"
           (string= "sha256-after" (delta-after delta)))
    (check "delta timestamp is a positive integer"
           (plusp (delta-timestamp delta)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 3. with-session: SESSION AS AUTHORITY NAMESPACE
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; "You just construct a session view and observe inside the namespace."

(defun test-with-session-namespace ()
  (format t "~%── with-session namespace ──~%")

  (let ((alice-session (make-session "alice"
                                     (list (data-read-entry) (session-entry))
                                     epoch-42)))
    ;; Observe inside session namespace.
    (check "observe within session namespace"
           (with-session alice-session
             (multiple-value-bind (tag path)
                 (observe "/data/session/alice.json")
               (declare (ignore path))
               (eq :observed tag))))

    ;; Commit within session namespace — write to session path.
    (check "commit! within session namespace"
           (with-session alice-session
             (delta-p (commit! (make-fs-effect :write "/data/session/state.json" "{}")))))

    ;; commit! outside session's authority fails.
    (check "commit! to unauthorized path fails within session"
           (with-session alice-session
             (handler-case
                 (progn (commit! (make-fs-effect :write "/etc/passwd" "evil")) nil)
               (capability-error () t))))

    ;; Epoch from session is embedded in delta.
    (check "delta epoch matches session epoch"
           (with-session alice-session
             (= epoch-42 (delta-epoch (commit! (make-fs-effect :write "/data/session/x.json" ""))))))))

(defparameter epoch-42 42)

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 4. COMMITMENT ACROSS PROVIDER TYPES
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-multi-provider-commit ()
  (format t "~%── multi-provider commit ──~%")

  ;; Process signal.
  (check "signal commit within pid authority"
         (with-cap (pid-entry 1234)
           (delta-p (commit! (make-process-effect :signal 1234)))))

  (check "signal commit to wrong pid fails"
         (with-cap (pid-entry 1234)
           (handler-case
               (progn (commit! (make-process-effect :signal 9999)) nil)
             (capability-error () t))))

  ;; HTTP call.
  (check "http GET commit within http authority"
         (with-cap (api-entry)
           (delta-p (commit! (make-http-effect :get "https://api.example.com/v1/users")))))

  (check "http GET to unauthorized URL fails"
         (with-cap (api-entry)
           (handler-case
               (progn (commit! (make-http-effect :get "https://evil.com/steal")) nil)
             (capability-error () t))))

  ;; IPC send.
  (let ((fd3-entry (make-instance 'authority-entry
                                  :resource (make-instance 'ipc-fd-resource :fd 3)
                                  :ops (op-set :send))))
    (check "ipc send on fd 3 within authority"
           (with-cap fd3-entry
             (delta-p (commit! (make-ipc-effect :send 3 "ping")))))
    (check "ipc send on fd 4 fails when only fd 3 authorized"
           (with-cap fd3-entry
             (handler-case
                 (progn (commit! (make-ipc-effect :send 4 "ping")) nil)
               (capability-error () t))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 5. REPLAY EVAL INVARIANT
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; "Every evaluation produces a delta; re-evaluation from that delta is
;;;  definitionally equivalent."

(defun test-replay-invariant ()
  (format t "~%── replay eval invariant ──~%")

  (let* ((auth  (data-write-entry))
         ;; Original evaluation.
         (d1    (with-cap auth
                  (commit! (make-fs-effect :write "/data/out.json" "v1")
                           :before "hash-0"
                           :after  "hash-1"))))

    ;; Re-evaluation produces an equivalent delta.
    (check "replay of same effect produces equivalent delta"
           (verify-replay-invariant d1
            (lambda ()
              (commit! (make-fs-effect :write "/data/out.json" "v1")
                       :before "hash-0"
                       :after  "hash-1"))))

    ;; Different payload → not equivalent.
    (check "different payload → replay invariant violated"
           (handler-case
               (progn
                 (verify-replay-invariant d1
                  (lambda ()
                    (commit! (make-fs-effect :write "/data/out.json" "v2")  ; different payload
                             :before "hash-0"
                             :after  "hash-2")))
                 nil)
             (error () t)))

    ;; Different resource → not equivalent.
    (check "different resource → replay invariant violated"
           (handler-case
               (progn
                 (verify-replay-invariant d1
                  (lambda ()
                    (commit! (make-fs-effect :write "/data/other.json" "v1")
                             :before "hash-0"
                             :after  "hash-1")))
                 nil)
             (error () t)))

    ;; :unknown states match anything — replay without state is still valid.
    (let ((d-unknown (with-cap auth
                       (commit! (make-fs-effect :write "/data/out.json" "v1")))))
      (check "unknown state matches known state in replay"
             (deltas-equivalent-p d-unknown d1)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 6. STATIC SCOPE VERIFIER
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-static-scope-verifier ()
  (format t "~%── static scope verifier ──~%")

  ;; Valid program: commit! inside with-cap.
  (check "valid: commit! inside with-cap passes static check"
         (verify-cap-scope
          '(with-cap auth-entries
             (commit! (make-fs-effect :write "/data/out.json" "x")))
          (list (data-write-entry))))

  ;; Valid: observe inside with-cap with read authority.
  (check "valid: observe inside with-cap with read authority"
         (verify-cap-scope
          '(with-cap auth-entries
             (observe "/data/profile.json"))
          (list (data-read-entry))))

  ;; Invalid: commit! with no authority in scope.
  (check "invalid: commit! with no authority signals static error"
         (handler-case
             (progn
               (verify-cap-scope
                '(commit! (make-fs-effect :write "/data/secret.json" "x"))
                nil)
               nil)
           (static-scope-error () t)))

  ;; Invalid: observe with no read authority.
  (check "invalid: observe with no authority signals static error"
         (handler-case
             (progn
               (verify-cap-scope
                '(observe "/data/profile.json")
                nil)
               nil)
           (static-scope-error () t)))

  ;; Nested: commit! in inner scope has access to outer + inner authority.
  (check "valid: nested with-cap scopes compose"
         (verify-cap-scope
          `(with-cap auth1
             (with-cap auth2
               (commit! (make-fs-effect :write "/data/session/x.json" "y"))))
          (list (data-write-entry)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 7. SESSION DELTA LOG + HISTORY
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-session-delta-log ()
  (format t "~%── session delta log ──~%")

  (let* ((sess (make-session "worker-17" (list (session-entry)) 10))
         d1 d2)
    ;; Commit two effects and push deltas to session history.
    (with-session sess
      (setf d1 (commit! (make-fs-effect :write "/data/session/a.json" "alpha")))
      (setf d2 (commit! (make-fs-effect :write "/data/session/b.json" "beta")))
      (session-push-delta sess d1)
      (session-push-delta sess d2))

    (check "session has 2 deltas in history"
           (= 2 (length (session-deltas sess))))
    (check "most-recent delta is second commit (pushed last)"
           (string= "/data/session/b.json"
                    (effect-resource-spec (delta-effect (first (session-deltas sess))))))
    (check "both deltas have session epoch 10"
           (every (lambda (d) (= 10 (delta-epoch d))) (session-deltas sess)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; 8. DSL SURFACE → OPERATIONAL PIPELINE
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Parse a (cap delegate ...) form → capability → with-cap → commit!

(defun test-cap-form-to-commit ()
  (format t "~%── cap form → with-cap → commit! ──~%")

  (let* ((cap (parse-capability
               '(cap delegate
                  (subject worker-17)
                  (authority
                   (fs (read "/data/**"))
                   (fs (write "/data/session/**")))
                  (conditions (epoch 42)))))
         d)
    ;; Use the parsed capability directly in with-cap.
    (setf d (with-cap cap
              (commit! (make-fs-effect :write "/data/session/state.json" "{}"))))

    (check "parsed cap + with-cap + commit! succeeds"
           (delta-p d))
    (check "delta effect matches committed operation"
           (and (eq :write (effect-kind (delta-effect d)))
                (string= "/data/session/state.json"
                         (effect-resource-spec (delta-effect d)))))

    ;; commit! to a resource outside the parsed cap's authority fails.
    (check "commit! outside parsed cap's scope fails"
           (with-cap cap
             (handler-case
                 (progn (commit! (make-fs-effect :write "/etc/cron.d/evil" "x")) nil)
               (capability-error () t))))))

;;; ── Runner ───────────────────────────────────────────────────────────────────

(defun run-all-tests ()
  (setf *pass* 0 *fail* 0)
  (format t "~%═══ authority-dsl operational semantics tests ═══~%")
  (test-with-cap-scope)
  (test-commit-delta)
  (test-with-session-namespace)
  (test-multi-provider-commit)
  (test-replay-invariant)
  (test-static-scope-verifier)
  (test-session-delta-log)
  (test-cap-form-to-commit)
  (format t "~%Results: ~a passed, ~a failed~%" *pass* *fail*)
  (zerop *fail*))

(run-all-tests)
