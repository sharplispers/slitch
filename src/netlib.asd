(defpackage #:netlib-system (:use #:cl #:asdf))
(in-package :netlib-system)

(defsystem netlib
    :components
    ((:file "root")
     (:file "tuntap")
     (:file "packet-socket")
     (:file "binary-types")
     (:file "binary-types-extra"
            :depends-on ("binary-types"))
     (:file "binary-rw-gen"
            :depends-on ("binary-types-extra"))
     (:file "netlib-package"
            :depends-on ("root" "tuntap" "packet-socket" "binary-rw-gen"))
     (:file "netlib"
            :depends-on ("netlib-package"
                         "netlib-constants"
                         "netlib-structures"))
     (:file "netlib-structures"
            :depends-on ("netlib-package"))
     (:file "netlib-constants"
            :depends-on ("netlib-package" "netlib-structures"))
     (:file "window"
            :depends-on ("netlib"))
     (:file "tcpip"
            :depends-on ("netlib" "window"))))
