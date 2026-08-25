(defsystem "authority-dsl"
  :description "Cross-provider typed authority IR with monotonic attenuation verification"
  :version "0.1.0"
  :author "Solarplex"
  :license "MIT"
  :depends-on ()
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "algebra")
     (:file "ir")
     (:file "parser")
     (:file "normalizer")
     (:file "verifier")
     (:file "operational")
     (:file "saga")
     (:file "serializer")
     (:module "backends"
      :serial t
      :components
      ((:file "linux")))))))

(defsystem "authority-dsl/tests"
  :description "Tests for authority-dsl"
  :depends-on ("authority-dsl")
  :serial t
  :components
  ((:module "tests"
    :serial t
    :components
    ((:file "test-verifier")
     (:file "test-e2e")
     (:file "test-syntax")
     (:file "test-operational")
     (:file "test-saga")
     (:file "test-serializer"))))
  :perform (asdf:test-op (op c)
             (uiop:symbol-call '#:authority-dsl/tests/verifier    '#:run-all-tests)
             (uiop:symbol-call '#:authority-dsl/tests/e2e         '#:run-all-tests)
             (uiop:symbol-call '#:authority-dsl/tests/syntax      '#:run-all-tests)
             (uiop:symbol-call '#:authority-dsl/tests/operational '#:run-all-tests)
             (uiop:symbol-call '#:authority-dsl/tests/saga        '#:run-saga-tests)
             (uiop:symbol-call '#:authority-dsl/tests/serializer  '#:run-serializer-tests)))

