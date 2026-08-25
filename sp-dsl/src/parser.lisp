(defpackage #:authority-dsl/parser
  (:use #:cl #:authority-dsl/algebra #:authority-dsl/ir)
  (:export
   ;; Graph-based (original) API
   #:parse-authority-graph
   #:parse-authority-entry
   #:parse-resource
   #:parse-root
   #:parse-principal
   #:parse-delegation
   ;; Capability document API
   #:parse-capability
   #:parse-cap-conditions
   #:parse-cap-authority
   ;; Shared
   #:parser-error))

(in-package #:authority-dsl/parser)

;;; ── Errors ───────────────────────────────────────────────────────────────────

(define-condition parser-error (error)
  ((message :initarg :message :reader parser-error-message)
   (form    :initarg :form    :reader parser-error-form :initform nil))
  (:report (lambda (c s)
             (format s "authority-dsl parser error: ~a~@[ in form ~s~]"
                     (parser-error-message c) (parser-error-form c)))))

(defun %parse-error (msg &optional form)
  (error 'parser-error :message msg :form form))

(defun %normalize-symbols (form)
  "Re-intern every non-keyword symbol in FORM into the parser package.
   This makes case/eq dispatch work regardless of which package the caller
   used when constructing or reading the form."
  (let ((pkg (load-time-value (find-package '#:authority-dsl/parser))))
    (labels ((walk (x)
               (cond ((and (symbolp x) (not (keywordp x)))
                      (intern (symbol-name x) pkg))
                     ((consp x)
                      (cons (walk (car x)) (walk (cdr x))))
                     (t x))))
      (walk form))))

;;; ── Entry point ──────────────────────────────────────────────────────────────
;;; Accepts either a string (READ'd) or an already-parsed s-expression tree.
;;; The top-level form is:
;;;
;;;   (authority-graph
;;;     (roots ...)
;;;     (principals ...)
;;;     (delegate ...)*)
;;;
;;; or a list of sub-forms.

(defun parse-authority-graph (source)
  "Parse SOURCE (string or s-expression) into an AUTHORITY-GRAPH.
   Returns the graph or signals PARSER-ERROR."
  (let ((form (%normalize-symbols
               (if (stringp source) (read-from-string source) source))))
    (unless (and (consp form) (eq (car form) 'authority-graph))
      (%parse-error "expected (authority-graph ...)" form))
    (let ((graph (make-authority-graph)))
      (dolist (clause (cdr form))
        (%process-clause graph clause))
      graph)))

(defun %process-clause (graph clause)
  (unless (consp clause) (%parse-error "expected a clause list" clause))
  (case (car clause)
    (roots
     (dolist (root-form (cdr clause))
       (let ((node (parse-root-node root-form)))
         (graph-add-node graph node)
         (push node (graph-roots graph)))))
    (principals
     (dolist (p-form (cdr clause))
       (graph-add-node graph (parse-cap-node p-form))))
    (delegate
     (graph-add-delegation graph (parse-delegation-form (cdr clause))))
    (otherwise
     (%parse-error "unknown clause" (car clause)))))

;;; ── Parsing helpers ──────────────────────────────────────────────────────────

;;; (root :kind :ambient-os :provider :linux :id "shim"
;;;        :authority ((fs /data/** :read :write)))
(defun parse-root-node (form)
  (unless (and (consp form) (eq (car form) 'root))
    (%parse-error "expected (root ...)" form))
  (let* ((plist (cdr form))
         (id    (or (getf plist :id) (%parse-error ":id required in root" form)))
         (kind  (or (getf plist :kind) (%parse-error ":kind required in root" form)))
         (prov  (or (getf plist :provider) :linux))
         (prov-extra (getf plist :provenance))
         (auth-forms (getf plist :authority))
         (root   (make-instance 'root-authority :kind kind :provider prov
                                                :provenance prov-extra))
         (auth   (mapcar #'parse-authority-entry auth-forms))
         (prin   (make-instance 'principal :id id)))
    (make-instance 'cap-node :principal prin :authority auth :root root)))

;;; (principal :id "adapter"
;;;            :authority ((fs /tmp/** :read)))
(defun parse-cap-node (form)
  (unless (and (consp form) (eq (car form) 'principal))
    (%parse-error "expected (principal ...)" form))
  (let* ((plist (cdr form))
         (id    (or (getf plist :id) (%parse-error ":id required in principal" form)))
         (auth-forms (getf plist :authority))
         (auth  (mapcar #'parse-authority-entry auth-forms))
         (prin  (make-instance 'principal :id id)))
    (make-instance 'cap-node :principal prin :authority auth :root nil)))

;;; (delegate :from "shim" :to "adapter"
;;;           :authority ((fs /data/** :read)))
(defun parse-delegation-form (plist)
  (let* ((from  (or (getf plist :from) (%parse-error ":from required in delegate")))
         (to    (or (getf plist :to)   (%parse-error ":to required in delegate")))
         (auth  (mapcar #'parse-authority-entry (getf plist :authority))))
    (make-instance 'delegation :grantor from :grantee to :authority auth)))

;;; Authority entry: (fs /data/** :read :write &key :ttl 3600 :single-use t)
;;;                  (net example.com / :get :post)
;;;                  (pid :any :signal :kill)
;;;                  (ipc-fd 3 :send :recv)
;;;                  (http https://api.example.com/** :get)
(defun parse-authority-entry (form)
  (setf form (%normalize-symbols form))
  (unless (consp form) (%parse-error "expected authority entry list" form))
  (destructuring-bind (provider-kw resource-spec &rest rest) form
    (let* ((conditions-plist (parse-conditions rest))
           (ops-keywords (remove-if (lambda (x) (member x '(:ttl :quorum :single-use :audit))) rest))
           (ops (apply #'op-set ops-keywords))
           (cond-obj (when conditions-plist (apply #'condition-set conditions-plist)))
           (resource (parse-resource provider-kw resource-spec form)))
      (make-instance 'authority-entry :resource resource :ops ops :conditions cond-obj))))

(defun parse-conditions (rest)
  "Extract condition keys from REST (ttl, quorum, single-use, audit)."
  (loop for (key val) on rest by #'cddr
        when (member key '(:ttl :quorum :single-use :audit))
        collect key and collect val))

(defun parse-resource (provider-kw spec form)
  (case provider-kw
    ((fs :fs :linux-fs)
     (unless (or (stringp spec) (symbolp spec))
       (%parse-error "fs resource expects a path glob" form))
     (make-instance 'fs-resource :path (path-glob (string-downcase (string spec)))))
    ((net :net :linux-net)
     ;; spec may be: host-string | (host port) | (host port-min port-max)
     (cond
       ((or (stringp spec) (symbolp spec))
        (make-instance 'net-resource :host (string-downcase (string spec))))
       ((and (consp spec) (= (length spec) 2))
        (make-instance 'net-resource :host (string (first spec))
                                     :port-min (second spec) :port-max (second spec)))
       ((and (consp spec) (= (length spec) 3))
        (make-instance 'net-resource :host (string (first spec))
                                     :port-min (second spec) :port-max (third spec)))
       (t (%parse-error "net resource expects host, (host port), or (host min max)" form))))
    ((pid :pid :linux-pid)
     (make-instance 'pid-resource :ref (if (eq spec :any) :any spec)))
    ((ipc-fd :ipc-fd)
     (make-instance 'ipc-fd-resource :fd (if (eq spec :inherited) :any spec)))
    ((http :http :http-ucan)
     (unless (or (stringp spec) (symbolp spec))
       (%parse-error "http resource expects a URL pattern" form))
     (make-instance 'http-resource :url-pattern (string spec) :methods (op-set)))
    ((wasm :wasm)
     (unless (or (stringp spec) (symbolp spec))
       (%parse-error "wasm resource expects a module id or *" form))
     (make-instance 'wasm-resource :module (string spec)))
    (otherwise
     (%parse-error (format nil "unknown provider ~s" provider-kw) form))))

;;; ── Public parse-* aliases for standalone use ────────────────────────────────

(defun parse-resource-form (form)
  "Parse a single (provider spec) form into a RESOURCE."
  (unless (consp form) (%parse-error "expected (provider spec)" form))
  (parse-resource (first form) (second form) form))

(defun parse-principal (form)
  "Parse a principal id string or (principal :id ...) form."
  (cond ((stringp form) (make-instance 'principal :id form))
        ((and (consp form) (eq (car form) 'principal))
         (make-instance 'principal :id (getf (cdr form) :id)))
        (t (%parse-error "expected string id or (principal ...)" form))))

(defun parse-root (form)
  (parse-root-node form))

(defun parse-delegation (form)
  (unless (and (consp form) (eq (car form) 'delegate))
    (%parse-error "expected (delegate ...)" form))
  (parse-delegation-form (cdr form)))

;;; ══════════════════════════════════════════════════════════════════════════════
;;; CAPABILITY DOCUMENT PARSER
;;; ══════════════════════════════════════════════════════════════════════════════
;;;
;;; Parses the richer surface syntax:
;;;
;;;   (cap delegate
;;;     (subject worker-17)
;;;     (authority
;;;       (fs   (read "/data/**") (write "/tmp/**"))
;;;       (process (signal (pid 1234)))
;;;       (http (get "https://api.example.com/v1/**")))
;;;     (derived-from root-session-42/alice)
;;;     (conditions
;;;       (expires "2026-07-04T20:00:00Z")
;;;       (quorum guardian+human)
;;;       (epoch 42)))
;;;
;;; Note on pid:1234 — the colon form is a CL package reference and will cause
;;; a reader error if the PID package is not defined.  Use (pid 1234) instead,
;;; or the string "pid:1234".  The parser handles both (pid N) and :any.
;;;
;;; Note on namespace/mount (Example 1 syntax) — this maps to a :linux-ns
;;; provider via parse-namespace-block; see below.

(defun parse-capability (source)
  "Parse a (cap ACTION ...) form into a CAPABILITY object.
   SOURCE may be a string (READ'd) or an already-parsed s-expression."
  (let ((form (%normalize-symbols
               (if (stringp source) (read-from-string source) source))))
    (unless (and (consp form) (eq (car form) 'cap))
      (%parse-error "expected (cap action ...)" form))
    (destructuring-bind (cap-kw action &rest clauses) form
      (declare (ignore cap-kw))
      (let ((action-kw (intern (string-upcase (string action)) :keyword))
            subject authority derived-from conditions metadata)
        (unless (member action-kw '(:delegate :invoke))
          (%parse-error (format nil "unknown cap action ~s; expected delegate or invoke" action) form))
        (dolist (clause clauses)
          (unless (consp clause) (%parse-error "expected a clause" clause))
          (case (car clause)
            (subject
             (setf subject (string (second clause))))
            (authority
             (setf authority (parse-cap-authority (cdr clause))))
            (derived-from
             (setf derived-from (string (second clause))))
            (conditions
             (setf conditions (parse-cap-conditions (cdr clause))))
            (meta
             (setf metadata (cdr clause)))
            (otherwise
             (%parse-error (format nil "unknown cap clause ~s" (car clause)) clause))))
        (unless subject (%parse-error "cap form missing (subject ...)" form))
        (make-instance 'capability
                       :action       action-kw
                       :subject      subject
                       :authority    (or authority nil)
                       :derived-from derived-from
                       :conditions   conditions
                       :metadata     metadata)))))

;;; ── Op-first authority block ──────────────────────────────────────────────────
;;; (authority
;;;   (fs   (read "/data/**") (write "/tmp/**"))
;;;   (process (signal (pid 1234)))
;;;   (net  (connect "example.com"))
;;;   (http (get "https://api.example.com/**"))
;;;   (wasm (execute "safe-module"))
;;;   (ipc-fd (send (fd 3)) (recv (fd 3)))
;;;   (namespace (mount "/data" :read) (mount "/logs" :append)))

(defun parse-cap-authority (provider-blocks)
  "Parse a list of (provider op-form...) blocks into a flat list of authority-entry."
  (loop for block in provider-blocks
        append (parse-provider-block block)))

(defun parse-provider-block (block)
  "Parse one (provider (op resource...) ...) block into a list of authority-entry."
  (unless (consp block) (%parse-error "expected (provider ...) block" block))
  (let ((provider-kw (car block))
        (op-forms    (cdr block)))
    (case provider-kw
      ;; namespace/mount — Example 1 syntax
      ((namespace :namespace :linux-ns)
       (parse-namespace-block op-forms))
      ;; All other providers: each op-form is (op resource-spec...)
      (otherwise
       (mapcar (lambda (op-form) (parse-op-form provider-kw op-form))
               op-forms)))))

(defun parse-op-form (provider-kw op-form)
  "Parse a single (op resource-spec...) into an authority-entry.
   Examples:
     (read \"/data/**\")
     (signal (pid 1234))
     (get \"https://api.example.com/**\")
     (send (fd 3))"
  (unless (consp op-form) (%parse-error "expected (op resource...)" op-form))
  (let* ((op      (intern (string-upcase (string (car op-form))) :keyword))
         (res-spec (cdr op-form))
         (resource (parse-cap-resource provider-kw res-spec op-form)))
    (make-instance 'authority-entry
                   :resource resource
                   :ops      (op-set op))))

(defun parse-cap-resource (provider-kw res-spec context)
  "Parse resource-spec within an op-form for the given provider."
  (case provider-kw
    ((fs :fs :linux-fs)
     (let ((path (first res-spec)))
       (unless path (%parse-error "fs op-form missing path" context))
       (make-instance 'fs-resource :path (path-glob (string path)))))
    ((process :process :linux-pid pid :pid :linux-pid)
     ;; res-spec may be (pid N), :any, or a bare integer
     (let ((ref (parse-pid-ref (first res-spec))))
       (make-instance 'pid-resource :ref ref)))
    ((net :net :linux-net)
     (let ((host (first res-spec)))
       (unless host (%parse-error "net op-form missing host" context))
       (make-instance 'net-resource :host (string host))))
    ((http :http :http-ucan)
     (let ((url (first res-spec)))
       (unless url (%parse-error "http op-form missing URL" context))
       (make-instance 'http-resource :url-pattern (string url) :methods (op-set))))
    ((wasm :wasm)
     (let ((module (first res-spec)))
       (unless module (%parse-error "wasm op-form missing module" context))
       (make-instance 'wasm-resource :module (string module))))
    ((ipc-fd :ipc-fd)
     (let ((fd-ref (parse-fd-ref (first res-spec))))
       (make-instance 'ipc-fd-resource :fd fd-ref)))
    (otherwise
     (%parse-error (format nil "unknown provider in op-form: ~s" provider-kw) context))))

(defun parse-pid-ref (spec)
  "Parse a pid reference: :any, integer, (pid N), or string."
  (cond ((eq spec :any)    :any)
        ((integerp spec)   spec)
        ((and (consp spec) (member (car spec) '(pid :pid)))
         (second spec))
        ((stringp spec)
         (if (string= spec "any") :any (parse-integer spec :junk-allowed t)))
        (t :any)))

(defun parse-fd-ref (spec)
  "Parse an fd reference: :any, integer, (fd N)."
  (cond ((eq spec :any)    :any)
        ((integerp spec)   spec)
        ((and (consp spec) (member (car spec) '(fd :fd)))
         (second spec))
        (t :any)))

;;; ── Namespace/mount block (Example 1 syntax) ─────────────────────────────────
;;; (namespace
;;;   (mount "/data" :read)
;;;   (mount "/logs" :append))
;;;
;;; Lowered to :linux-fs entries — mount points are paths, ops are the access mode.

(defun parse-namespace-block (mount-forms)
  (mapcar #'parse-mount-form mount-forms))

(defun parse-mount-form (form)
  "Parse (mount path op...) into a :linux-fs authority-entry."
  (unless (and (consp form) (member (car form) '(mount :mount)))
    (%parse-error "expected (mount path op...)" form))
  (destructuring-bind (_mount path &rest ops) form
    (declare (ignore _mount))
    (make-instance 'authority-entry
                   :resource (make-instance 'fs-resource :path (path-glob (string path)))
                   :ops      (apply #'op-set ops))))

;;; ── Conditions block ──────────────────────────────────────────────────────────
;;; (conditions
;;;   (expires "2026-07-04T20:00:00Z")  ; ISO-8601 → unix timestamp
;;;   (expires t)                        ; must expire, time not specified here
;;;   (quorum guardian+human)            ; symbolic party set
;;;   (quorum 2)                         ; numeric threshold
;;;   (epoch 42)                         ; monotonic counter
;;;   (single-use t)
;;;   (audit t))

(defun parse-cap-conditions (condition-forms)
  "Parse a list of condition forms into a CONDITION-SET."
  (let (plist)
    (dolist (form condition-forms)
      (unless (consp form) (%parse-error "expected (key value) condition" form))
      (destructuring-bind (key &optional val) form
        (case key
          (expires
           (cond ((eq val t)
                  ;; Boolean: records that expiry is required without a specific time.
                  (setf (getf plist :single-use) t))
                 ((stringp val)
                  (setf (getf plist :expires-at) (parse-iso8601-to-unix val)))
                 ((integerp val)
                  (setf (getf plist :expires-at) val))
                 (t (%parse-error "expires expects t, ISO string, or unix int" form))))
          (quorum
           (setf (getf plist :quorum) (parse-quorum val)))
          (epoch
           (unless (integerp val) (%parse-error "epoch expects integer" form))
           (setf (getf plist :epoch) val))
          (single-use
           (setf (getf plist :single-use) val))
          (audit
           (setf (getf plist :audit) val))
          (ttl
           (unless (integerp val) (%parse-error "ttl expects integer seconds" form))
           (setf (getf plist :ttl) val))
          (otherwise
           (%parse-error (format nil "unknown condition key ~s" key) form)))))
    (when plist (apply #'condition-set plist))))

(defun parse-quorum (val)
  "Parse a quorum value: integer, symbol, or list of symbols.
   guardian+human  → (:guardian :human)  (splits on +, keywords for stability)
   guardian        → :guardian
   2               → 2 (numeric threshold)"
  (cond ((integerp val) val)
        ((symbolp val)
         ;; Split compound symbols on + to get party list; intern as keywords
         ;; so they are package-independent and comparable across call sites.
         (let* ((s (symbol-name val))
                (parts (split-on-char s #\+)))
           (if (= 1 (length parts))
               (intern s :keyword)
               (mapcar (lambda (p) (intern p :keyword)) parts))))
        ((listp val) (mapcar (lambda (p) (intern (symbol-name p) :keyword)) val))
        (t val)))

(defun split-on-char (s char)
  "Split string S on CHAR, returning a list of substrings."
  (loop with start = 0
        for i from 0 below (length s)
        when (char= (char s i) char)
          collect (subseq s start i) into parts
          and do (setf start (1+ i))
        finally (return (append parts (list (subseq s start))))))

(defun parse-iso8601-to-unix (s)
  "Parse an ISO-8601 string to a Unix timestamp (integer seconds).
   Handles YYYY-MM-DDTHH:MM:SSZ only.  Returns 0 on parse failure."
  (handler-case
      (let* ((year   (parse-integer s :start 0  :end 4))
             (month  (parse-integer s :start 5  :end 7))
             (day    (parse-integer s :start 8  :end 10))
             (hour   (parse-integer s :start 11 :end 13))
             (minute (parse-integer s :start 14 :end 16))
             (sec    (parse-integer s :start 17 :end 19))
             ;; Proleptic Gregorian day count from Unix epoch.
             (jdn    (+ (* 365 year)
                        (floor year 4) (- (floor year 100)) (floor year 400)
                        (floor (* 367 month) 12) day -719499)))
        (+ (* jdn 86400) (* hour 3600) (* minute 60) sec))
    (error () 0)))
