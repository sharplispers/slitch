;;; switch-types.lisp -- datatypes

(in-package "SWITCH")

;; ============================================================
;; Protocol data structures

(define-unsigned u48 6)

(define-binary-vector ip-addr-octets  u8 4)
(define-binary-vector mac-addr-octets u8 6)

(define-binary-struct (ip-addr (:print-function print-ip-addr)) ()
  (value nil :binary-type ip-addr-octets))

(define-binary-struct (mac-addr (:print-function print-mac-addr)) ()
  (value nil :binary-type mac-addr-octets))

(define-binary-struct ethh ()
  (dest nil :binary-type mac-addr)
  (src  nil :binary-type mac-addr)
  (type nil :binary-type u16)
  (:documentation "Ethernet frame header."))

(define-binary-struct arph ()
  (hardware-type   nil :binary-type u16)
  (protocol-type   nil :binary-type u16)
  (hardware-length nil :binary-type u8)
  (protocol-length nil :binary-type u8)
  (operation       nil :binary-type u16)
  (sender-ha       nil :binary-type mac-addr) ; ha = hardware address
  (sender-ip       nil :binary-type ip-addr)
  (target-ha       nil :binary-type mac-addr)
  (target-ip       nil :binary-type ip-addr)
  (:documentation "ARP frame header."))

;; IP header.
;; See RFC 791, page 10

(define-unsigned-bitint ip-version         4)
(define-unsigned-bitint ip-header-length   4) ; IHL
(define-unsigned-bitint ip-type-of-service 8)
(define-unsigned-bitint ip-total-length    16)
(define-unsigned-bitint ip-identification  16)
(define-unsigned-bitint ip-flags           3)
(define-unsigned-bitint ip-fragment-offset 13)
(define-unsigned-bitint ip-time-to-live    8)
(define-unsigned-bitint ip-protocol        8)
(define-unsigned-bitint ip-header-checksum 16)

(define-binary-bitfield-struct iph ()
  (version         0 :binary-type ip-version)
  (hlen            0 :binary-type ip-header-length)
  (tos             0 :binary-type ip-type-of-service)
  (total-len       0 :binary-type ip-total-length)
  (id              0 :binary-type ip-identification)
  (flags           0 :binary-type ip-flags)
  (fragment-offset 0 :binary-type ip-fragment-offset)
  (ttl             0 :binary-type ip-time-to-live)
  (protocol        0 :binary-type ip-protocol)
  (checksum        0 :binary-type ip-header-checksum)
  (source          0 :binary-type ip-addr)
  (dest            0 :binary-type ip-addr)
  (options         '()))

;; ICMP header. See rfc 792.

(define-binary-struct icmph ()
  (type     0 :binary-type u8)
  (code     0 :binary-type u8)
  (checksum 0 :binary-type u16))

(defmethod make-load-form ((s ip-addr) &optional env)
  (make-load-form-saving-slots s :environment env))

(defmethod make-load-form ((s mac-addr) &optional env)
  (make-load-form-saving-slots s :environment env))

(define-binary-struct udph ()
  ;; IP addresses are inherited from IP layer
  (src-ip      nil)
  (dest-ip     nil)
  (src-port  nil :binary-type u16)
  (dest-port nil :binary-type u16)
  (length    nil :binary-type u16)
  (checksum  0   :binary-type u16)
  (data      nil))

;; TCP header. See rfc 793.

(define-unsigned-bitint 1bit  1)
(define-unsigned-bitint 4bits 4)
(define-unsigned-bitint 6bits 6)

(define-binary-bitfield-struct tcph ()
  ;; IP addresses are inherited from IP layer
  (src-ip      nil)
  (dest-ip     nil)
  (src-port    nil :binary-type u16)
  (dest-port   nil :binary-type u16)
  (seq         nil :binary-type u32)
  (ack-seq     nil :binary-type u32)
  (data-offset nil :binary-type 4bits)
  (reserved    0   :binary-type 6bits)
  (urg?        nil :binary-type bitflag)
  (ack?        nil :binary-type bitflag)
  (psh?        nil :binary-type bitflag)
  (rst?        nil :binary-type bitflag)
  (syn?        nil :binary-type bitflag)
  (fin?        nil :binary-type bitflag)
  (window      nil :binary-type u16)
  (checksum    0   :binary-type u16)
  (urgent-ptr  0   :binary-type u16)
  (options     '())			; options (d)encoded by hand
  (data        nil)
  (:documentation "TCP header."))

(define-binary-bitfield-struct tcp-pseudo-iph ()
  ;; Pseudo IP header for TCP checksum calculation (RFC 793, page 17)
  (src-ip  nil :binary-type ip-addr)
  (dest-ip nil :binary-type ip-addr)
  (proto   nil :binary-type u16)
  (len     nil :binary-type u16))

;; TCP Stream ID structure
(defstruct
    (tcp-stream-id (:print-function print-tcp-stream-id)
		   (:constructor make-tcp-stream-id
				 (local-ip local-port remote-ip remote-port)))
  (local-ip    nil :type (or null ip-addr))
  (local-port  nil :type (or null (unsigned-byte 16)))
  (remote-ip   nil :type (or null ip-addr))
  (remote-port nil :type (or null (unsigned-byte 16))))

(defun print-tcp-stream-id (tcp stream depth)
  "Print a TCP stream like:
  #<TCP Stream 192.168.43.10:10 / 192.168.43.1:20>"
  (declare (ignore depth))
  (format stream "#<TCP Stream ~A:~A / ~A:~A>"
	  (ip-addr-to-string (tcp-stream-id-local-ip tcp))
	  (tcp-stream-id-local-port tcp)
	  (ip-addr-to-string (tcp-stream-id-remote-ip tcp))
	  (tcp-stream-id-remote-port tcp)))

;; ============================================================
;; Read syntax

;; Looks like this:
;;   @192.168.128.43       <=> ip-addr
;;   #e"F1:F2:F3:F4:F5:F6" <=> mac-addr

(defun read-ip-address (stream &optional c n)
  (declare (ignore c n))
  (let ((*readtable* (copy-readtable)))
    (set-syntax-from-char #\. #\Space)
    (let ((vec (make-array '(4) :element-type '(integer 0 255))))
      (dotimes (i 4)
	(setf (elt vec i) (read stream t nil t)))
      (make-ip-addr :value vec))))

(defun read-mac-address (stream &optional c n)
  (declare (ignore c n))
  (let ((value-stream (make-string-input-stream (read stream t nil t)))
        (*readtable* (copy-readtable))
	(*read-base* 16))
    (set-syntax-from-char #\: #\Space)
    (let ((vec (make-array '(6) :element-type '(integer 0 255))))
      (dotimes (i 6)
	(setf (elt vec i) (read value-stream t nil t)))
      (make-mac-addr :value vec))))

(set-dispatch-macro-character #\# #\e 'read-mac-address)
(set-macro-character #\@ 'read-ip-address t)

;; ============================================================
;; Printing

(defun print-ip-addr (ip stream depth)
  (declare (ignore depth))
  (format stream "@~A"
	  (ip-addr-to-string ip)))

(defun ip-addr-to-string (ip &optional print-null)
  (if (and (null ip) print-null)
      (ip-addr-to-string (make-ip-addr :value #(0 0 0 0)))
      (format nil "~{~A~^.~}" (to-list (ip-addr-value ip)))))

(defun print-mac-addr (mac stream depth)
  (declare (ignore depth))
  (format stream "#e\"~A\""
	  (mac-addr-to-string mac)))

(defun mac-addr-to-string (ip &optional print-null)
  (if (and (null ip) print-null)
      (mac-addr-to-string (make-mac-addr :value #(0 0 0 0 0 0)))
      (format nil "~{~16,2,'0R~^:~}" (to-list (mac-addr-value ip)))))

(defun to-list (seq)
  (map 'list #'identity seq))


;; ============================================================
;; Address manipulation

(defun ip-addr-to-int (ip)
  (octet-array-to-int (ip-addr-value ip)))

(defun int-to-ip-addr (ip)
  (make-ip-addr :value
                (make-array '(4)
                            :element-type '(integer 0 255)
                            :initial-contents (int-to-octet-array ip 4))))

(defun octet-array-to-int (array)
  (do ((i      (1- (length array)) (1- i))
       (offset 0 (+ offset 8))
       (n      0 (dpb (aref array i)
                      (byte 8 offset)
                      n)))
      ((< i 0) n)))

(defun int-to-octet-array (n size)
  (let ((array (make-array (list size) :initial-element NIL)))
    (loop for i from 0 below size
          for offset from (* 8 (1- size)) downto 0 by 8
          do (setf (aref array i) (ldb (byte 8 offset) n)))
    array))

(defmacro ip-arith ((&rest vars) expr)
  "Perform arithmetic with IP addresses.
VARS is a list of variables bound to IP addresses.

EXPR is evaluated with each VAR bound to the integer representing its
address. The result of EXPR, and integer, it returned as an IP address.

For example:

  (let ((x @192.168.128.1)
        (y @255.255.0.0))
    (ip-arith (x y) (logand x y)))
  => @192.168.0.0"
  `(let ,(loop for var in vars
               collect `(,var (ip-addr-to-int ,var)))
    (int-to-ip-addr ,expr)))

(defun prefix-bits-to-netmask (n)
  "Return an IP-ADDR with the first N bits set to 1, and the rest 0.
For example:
  (PREFIX-BITS-TO-NETMASK 24) => @255.255.255.0"
  (declare (type (integer 0 32) n))
  (int-to-ip-addr (lognot (1- (expt 2 (- 32 n))))))

(defun netmask-to-prefix-bits (mask)
  (loop for n = (ip-addr-to-int mask) then (ash n -1)
        for bits downfrom 32
        until (or (zerop bits) (= 1 (logand n 1)))
        finally (return bits)))

(defun mask-ip (ip mask)
  (ip-arith (ip mask) (logand ip mask)))

(defun broadcast-ip (network-address netmask)
  (ip-arith (network-address netmask)
            (logior network-address (lognot netmask))))

(defun ip>= (a b)
  (not (ip< a b)))

(defun ip< (a b)
  (let ((av (ip-addr-value a))
        (bv (ip-addr-value b)))
    (loop for x across av
          for y across bv
          when (< x y) do (return t))))

(defun as-netmask (number-or-mask)
  (etypecase number-or-mask
    (ip-addr number-or-mask)
    (integer (prefix-bits-to-netmask number-or-mask))))

(defun random-mac-addr ()
  "Return a mostly-random MAC address.
The first 16 bits are #x00FF and the rest are random.
This is how the Linux 'tap' driver chooses addresses for its
interfaces."
  (make-mac-addr :value (int-to-octet-array (dpb #xFF
                                                 (byte 16 32)
                                                 (random (expt 2 32)))
                                            6)))

