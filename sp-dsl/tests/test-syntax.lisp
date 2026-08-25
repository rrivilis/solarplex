(defpackage #:authority-dsl/tests/syntax
  (:use #:cl
        #:authority-dsl/algebra
        #:authority-dsl/ir
        #:authority-dsl/parser
        #:authority-dsl/normalizer
        #:authority-dsl/verifier))

(in-package #:authority-dsl/tests/syntax)

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

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SURFACE SYNTAX — Example 1
;;; namespace/mount delegation style
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-namespace-mount-syntax ()
  (format t "~%── namespace/mount syntax ──~%")
  (let* ((cap (parse-capability
               '(cap delegate
                  (subject worker-17)
                  (authority
                   (namespace
                    (mount "/data" :read)
                    (mount "/logs" :append)))
                  (conditions
                   (expires t)
                   (epoch 42)))))
         (auth (cap-authority cap))
         (cond (cap-conditions cap)))

    (check "action is :delegate"
           (eq :delegate (cap-action cap)))
    (check "subject is worker-17"
           (string= "WORKER-17" (cap-subject cap)))
    (check "two mount entries parsed"
           (= 2 (length auth)))
    (check "first entry is :linux-fs provider (mount lowered to fs)"
           (eq :linux-fs (resource-provider (entry-resource (first auth)))))
    (check "first mount path is /data"
           (string= "/data" (path-glob-pattern (fs-resource-path (entry-resource (first auth))))))
    (check "first mount op is :read"
           (member :read (ops (entry-ops (first auth)))))
    (check "second mount path is /logs"
           (string= "/logs" (path-glob-pattern (fs-resource-path (entry-resource (second auth))))))
    (check "second mount op is :append"
           (member :append (ops (entry-ops (second auth)))))
    (check "conditions parsed"
           (not (null cond)))
    (check "epoch condition is 42"
           (= 42 (getf (condition-set-conditions cond) :epoch)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; SURFACE SYNTAX — Example 2
;;; cap delegate / op-first authority / rich conditions
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-cap-delegate-syntax ()
  (format t "~%── cap delegate syntax ──~%")
  (let* ((cap (parse-capability
               '(cap delegate
                  (subject worker-17)
                  (authority
                   (fs   (read "/data/**"))
                   (process (signal (pid 1234)))
                   (http (get "https://api.example.com/v1/**")))
                  (derived-from root-session-42/alice)
                  (conditions
                   (expires "2026-07-04T20:00:00Z")
                   (quorum guardian+human)
                   (epoch 42)))))
         (auth (cap-authority cap))
         (cond (cap-conditions cap)))

    (check "action is :delegate"
           (eq :delegate (cap-action cap)))
    (check "subject string"
           (string= "WORKER-17" (cap-subject cap)))
    (check "derived-from parsed"
           (string= "ROOT-SESSION-42/ALICE" (cap-derived-from cap)))
    (check "three authority entries"
           (= 3 (length auth)))

    ;; fs entry
    (let ((fs-e (first auth)))
      (check "fs provider"
             (eq :linux-fs (resource-provider (entry-resource fs-e))))
      (check "fs path /data/**"
             (string= "/data/**" (path-glob-pattern (fs-resource-path (entry-resource fs-e)))))
      (check "fs op :read"
             (member :read (ops (entry-ops fs-e)))))

    ;; process/pid entry
    (let ((pid-e (second auth)))
      (check "pid provider"
             (eq :linux-pid (resource-provider (entry-resource pid-e))))
      (check "pid ref is 1234"
             (= 1234 (pid-resource-ref (entry-resource pid-e))))
      (check "pid op :signal"
             (member :signal (ops (entry-ops pid-e)))))

    ;; http entry
    (let ((http-e (third auth)))
      (check "http provider"
             (eq :http-ucan (resource-provider (entry-resource http-e))))
      (check "http url pattern"
             (string= "https://api.example.com/v1/**"
                      (http-resource-url-pattern (entry-resource http-e))))
      (check "http op :get"
             (member :get (ops (entry-ops http-e)))))

    ;; conditions
    (check "conditions present" (not (null cond)))
    (let ((cplist (condition-set-conditions cond)))
      (check "expires-at is a positive integer"
             (and (integerp (getf cplist :expires-at))
                  (> (getf cplist :expires-at) 0)))
      (check "quorum is a list (guardian human split from guardian+human)"
             (listp (getf cplist :quorum)))
      (check "quorum contains guardian"
             (member :guardian (getf cplist :quorum)))
      (check "quorum contains human"
             (member :human (getf cplist :quorum)))
      (check "epoch is 42"
             (= 42 (getf cplist :epoch))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; PID REFERENCE FORMS
;;; The (pid N) notation avoids the CL package-prefix issue with pid:1234
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-pid-reference-forms ()
  (format t "~%── pid reference forms ──~%")

  ;; (pid 1234) — preferred s-expression form
  (let ((cap (parse-capability
              '(cap delegate
                 (subject a)
                 (authority (process (signal (pid 1234))))))))
    (check "(pid 1234) parses as ref=1234"
           (= 1234 (pid-resource-ref
                    (entry-resource (first (cap-authority cap)))))))

  ;; Bare integer
  (let ((cap (parse-capability
              '(cap delegate
                 (subject a)
                 (authority (process (signal 5678)))))))
    (check "bare integer 5678 parses as ref=5678"
           (= 5678 (pid-resource-ref
                    (entry-resource (first (cap-authority cap)))))))

  ;; :any
  (let ((cap (parse-capability
              '(cap delegate
                 (subject a)
                 (authority (process (signal :any)))))))
    (check ":any parses as ref=:any"
           (eq :any (pid-resource-ref
                     (entry-resource (first (cap-authority cap))))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; CONDITIONS PARSING
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-conditions-parsing ()
  (format t "~%── conditions parsing ──~%")

  ;; Numeric quorum
  (let* ((cap (parse-capability '(cap delegate (subject a) (authority (fs (read "/**")))
                                    (conditions (quorum 2)))))
         (q (getf (condition-set-conditions (cap-conditions cap)) :quorum)))
    (check "numeric quorum 2" (= 2 q)))

  ;; Compound symbolic quorum a+b+c → (a b c)
  (let* ((cap (parse-capability '(cap delegate (subject a) (authority (fs (read "/**")))
                                    (conditions (quorum a+b+c)))))
         (q (getf (condition-set-conditions (cap-conditions cap)) :quorum)))
    (check "a+b+c splits into 3-element list" (= 3 (length q))))

  ;; Single symbolic quorum
  (let* ((cap (parse-capability '(cap delegate (subject a) (authority (fs (read "/**")))
                                    (conditions (quorum guardian)))))
         (q (getf (condition-set-conditions (cap-conditions cap)) :quorum)))
    (check "single guardian quorum" (eq :guardian q)))

  ;; expires t → :single-use
  (let* ((cap (parse-capability '(cap delegate (subject a) (authority (fs (read "/**")))
                                    (conditions (expires t)))))
         (su (getf (condition-set-conditions (cap-conditions cap)) :single-use)))
    (check "expires t → :single-use t" su))

  ;; expires ISO string → :expires-at unix int
  (let* ((cap (parse-capability '(cap delegate (subject a) (authority (fs (read "/**")))
                                    (conditions (expires "2026-07-04T20:00:00Z")))))
         (at (getf (condition-set-conditions (cap-conditions cap)) :expires-at)))
    (check "ISO expires → positive :expires-at integer" (and at (> at 0)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; CAPABILITY → DELEGATION LIFT + VERIFICATION
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-cap-to-delegation-verify ()
  (format t "~%── cap→delegation lift + verify ──~%")
  (let* (;; Root node: shim holds /data/** :read :write
         (root-auth (list (make-instance 'authority-entry
                                         :resource (make-instance 'fs-resource
                                                                  :path (path-glob "/data/**"))
                                         :ops (op-set :read :write))))
         (root-prin (make-instance 'principal :id "SHIM"))
         (root-node (make-instance 'cap-node :principal root-prin
                                             :authority root-auth
                                             :root (make-instance 'root-authority
                                                                  :kind :ambient-os
                                                                  :provider :linux)))
         ;; Capability: delegate /data/session/** :read to worker-17
         (cap (parse-capability
               '(cap delegate
                  (subject worker-17)
                  (authority
                   (fs (read "/data/session/**")))
                  (derived-from shim)
                  (conditions
                   (epoch 1)
                   (single-use t)))))
         ;; Lift capability to delegation edge.
         (edge (capability->delegation cap "shim"))
         (graph (make-authority-graph))
         (worker-auth (cap-authority cap))
         (worker-prin (make-instance 'principal :id "WORKER-17"))
         (worker-node (make-instance 'cap-node :principal worker-prin
                                               :authority worker-auth)))
    (graph-add-node graph root-node)
    (graph-add-node graph worker-node)
    (graph-add-delegation graph edge)

    (let ((result (verify-graph graph)))
      (check "cap → delegation verifies"
             (result-ok-p result))
      (check "delegation grantor is shim"
             (string= "SHIM" (delegation-grantor edge)))
      (check "delegation grantee is worker-17 (cap subject)"
             (string= "WORKER-17" (delegation-grantee edge)))
      (check "conditions propagated to entries"
             (not (null (entry-conditions (first (delegation-authority edge)))))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; QUORUM MONOTONICITY IN ALGEBRA
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-quorum-monotonicity ()
  (format t "~%── quorum condition monotonicity ──~%")
  (let* ((r   (make-instance 'fs-resource :path (path-glob "/data/**")))
         (ops (op-set :read))
         (entry (lambda (q)
                  (make-instance 'authority-entry :resource r :ops ops
                                 :conditions (condition-set :quorum q))))
         (e-guardian+human (funcall entry '(guardian human)))
         (e-guardian       (funcall entry '(guardian)))
         (e-2              (funcall entry 2))
         (e-1              (funcall entry 1)))

    ;; Set-based: (guardian human) ⊒ (guardian) — child requires superset
    (check "(guardian human) ⊒ (guardian): tighter"
           (authority-subset-p e-guardian+human e-guardian))
    (check "(guardian) ⋢ (guardian human): relaxed"
           (not (authority-subset-p e-guardian e-guardian+human)))

    ;; Numeric: 2 ⊒ 1
    (check "quorum 2 ⊒ 1" (authority-subset-p e-2 e-1))
    (check "quorum 1 ⋢ 2" (not (authority-subset-p e-1 e-2)))

    ;; Mixed: set-vs-numeric — set of 2 parties ⊒ threshold of 2
    (check "(guardian human) ⊒ quorum:2 (set size ≥ threshold)"
           (authority-subset-p e-guardian+human e-2))
    (check "(guardian) ⋢ quorum:2 (set size < threshold)"
           (not (authority-subset-p e-guardian e-2)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; EPOCH MONOTONICITY
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-epoch-monotonicity ()
  (format t "~%── epoch condition monotonicity ──~%")
  (let* ((r   (make-instance 'fs-resource :path (path-glob "/data/**")))
         (ops (op-set :read))
         (entry (lambda (epoch)
                  (make-instance 'authority-entry :resource r :ops ops
                                 :conditions (condition-set :epoch epoch)))))
    ;; Parent says epoch 42: child epoch ≥ 42 is acceptable (newer is tighter).
    (check "epoch 42 ⊒ epoch 42 (same)"
           (authority-subset-p (funcall entry 42) (funcall entry 42)))
    (check "epoch 43 ⊒ epoch 42 (newer)"
           (authority-subset-p (funcall entry 43) (funcall entry 42)))
    (check "epoch 41 ⋢ epoch 42 (stale)"
           (not (authority-subset-p (funcall entry 41) (funcall entry 42))))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; PARSER ERROR CASES — surface syntax
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-cap-parser-errors ()
  (format t "~%── cap parser errors ──~%")
  (check-error "missing subject" parser-error
    (parse-capability '(cap delegate (authority (fs (read "/"))))))
  (check-error "unknown action" parser-error
    (parse-capability '(cap destroy (subject a) (authority (fs (read "/"))))))
  (check-error "unknown clause" parser-error
    (parse-capability '(cap delegate (subject a) (authority (fs (read "/")))
                           (inject-evil))))
  (check-error "unknown condition key" parser-error
    (parse-capability '(cap delegate (subject a) (authority (fs (read "/")))
                           (conditions (badkey 99)))))
  (check-error "bad top form (not cap)" parser-error
    (parse-capability '(grant delegate (subject a)))))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; DETERMINISM: string form produces same canonical output
;;; ══════════════════════════════════════════════════════════════════════════════

(defun test-cap-canonical-determinism ()
  (format t "~%── cap canonical determinism ──~%")
  (let* ((src '(cap delegate
                 (subject worker-17)
                 (authority
                  (fs (read "/data/**"))
                  (http (get "https://api.example.com/v1/**")))
                 (conditions (epoch 5))))
         (cap-a (parse-capability src))
         (cap-b (parse-capability src))
         ;; Build identical graphs from each cap and compare canonical strings.
         (make-graph
          (lambda (cap)
            (let* ((g  (make-authority-graph))
                   (rp (make-instance 'principal :id "shim"))
                   (rn (make-instance 'cap-node :principal rp
                                      :authority (list
                                                  (make-instance 'authority-entry
                                                                 :resource (make-instance 'fs-resource :path (path-glob "/**"))
                                                                 :ops (op-set :read :write))
                                                  (make-instance 'authority-entry
                                                                 :resource (make-instance 'http-resource :url-pattern "/**" :methods (op-set))
                                                                 :ops (op-set :get :post)))
                                      :root (make-instance 'root-authority :kind :ambient-os :provider :linux)))
                   (wp (make-instance 'principal :id "WORKER-17"))
                   (wn (make-instance 'cap-node :principal wp :authority (cap-authority cap)))
                   (e  (capability->delegation cap "shim")))
              (graph-add-node g rn)
              (graph-add-node g wn)
              (graph-add-delegation g e)
              g))))
    (let* ((ga (funcall make-graph cap-a))
           (gb (funcall make-graph cap-b))
           (ca (canonicalize-graph (normalize-graph ga)))
           (cb (canonicalize-graph (normalize-graph gb))))
      (check "same source → same canonical string across two parses"
             (string= ca cb)))))

;;; ── Runner ───────────────────────────────────────────────────────────────────

(defun run-all-tests ()
  (setf *pass* 0 *fail* 0)
  (format t "~%═══ authority-dsl surface syntax tests ═══~%")
  (test-namespace-mount-syntax)
  (test-cap-delegate-syntax)
  (test-pid-reference-forms)
  (test-conditions-parsing)
  (test-cap-to-delegation-verify)
  (test-quorum-monotonicity)
  (test-epoch-monotonicity)
  (test-cap-parser-errors)
  (test-cap-canonical-determinism)
  (format t "~%Results: ~a passed, ~a failed~%" *pass* *fail*)
  (zerop *fail*))

(run-all-tests)
