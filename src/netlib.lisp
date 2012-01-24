;;; netlib.lisp -- low-level networking library

(in-package :netlib)

(deftype frame () '(simple-array (unsigned-byte 8) (*)))
(deftype packet ()
  "A packet is a list of protocol layer headers.  Headers are ordered
from lowest layer to highest. At any layer a binary frame can be given
instead of a header. Such a frame represents \"the rest\" of the
packet."
  '(or frame
       (cons ethh
             (or (cons frame null)
                 (cons arph null)
                 (cons iph
                       (or (cons frame null)
                           (cons (or udph icmph tcph) null)))))))

(defmacro with-input-from-frame ((var frame) &body body)
  `(with-binary-input-from-vector (,var ,frame)
    ,@body))

;;; 
;;; Network devices:

(defstruct device
  "Base structure for network devices.
Each slot holds a callback function implementing a piece of device
behaviour. The callbacks and their arguments are:

TX-FUN: DEVICE FRAME
  Transmits a frame.
ENABLE-FUN: DEVICE RX-FUN
  Enables the device to accept frames from the outside world. RX-FUN
  is called with each frame when it arrives.
DISABLE-FUN: DEVICE
  Disables the device. A disabled device will not accept packets until
  it is enabled again.
DESTROY-FUN: DEVICE
  Permanently shutdown the device."
  (tx-fun      (ext:required-argument) :type (or function symbol))
  (enable-fun  (ext:required-argument) :type (or function symbol))
  (disable-fun (ext:required-argument) :type (or function symbol))
  (destroy-fun (ext:required-argument) :type (or function symbol)))

(defun transmit (device frame)
  "Transmit FRAME on DEVICE."
  (funcall (device-tx-fun device) device frame))

(defun enable-device (device receive-fn)
  "Enable DEVICE to accept frames.
   RECEIVE-FN is called with each frame received."
  (funcall (device-enable-fun device) device receive-fn)
  t)

(defun disable-device (device)
  "Disable DEVICE from accepting frames."
  (funcall (device-disable-fun device) device)
  t)

(defun destroy-device (device)
  "Destroy DEVICE by shutting it down permanently."
  (funcall (device-destroy-fun device) device)
  t)

;;; 
;;; TAP device driver:

(defstruct (tapdev (:include device)
                   (:print-function print-tapdev))
  "TAP network device."
  (name (ext:required-argument) :type string)
  (fd   (ext:required-argument) :type integer))

(defun make-tap-device (name)
  "Make a TAP network device.
The TAP device is visible as a network interface called NAME on the
host machine. The host's interface can be configured to communicate
with the Lisp system using standard tools like 'ifconfig'.

TAP devices require the 'universal TUN/TAP device driver' to be loaded
on the host machine.
See /usr/src/linux/Documentation/networking/tuntap.txt for details."
  (make-tapdev :tx-fun 'tap-tx
               :enable-fun 'tap-enable
               :disable-fun 'tap-disable
               :destroy-fun 'tap-destroy
               :name name
               :fd (create-tunnel :tap name)))

(defun print-tapdev (dev stream depth)
  (declare (ignore depth))
  (print-unreadable-object (dev stream :type t :identity t)
    (format stream "~S (FD:~S)" (tapdev-name dev) (tapdev-fd dev))))

(defun tap-rx (dev)
  (tunnel-read (tapdev-fd dev)))

(defun tap-tx (dev frame)
  (tunnel-write (tapdev-fd dev) frame))

(defun tap-enable (dev rx-fun)
  (flet ((read-interface (fd)
           (declare (ignore fd))
           (let ((input-frame (tunnel-read (tapdev-fd dev))))
             (when input-frame
               (funcall rx-fun input-frame)))))
    (system:add-fd-handler (tapdev-fd dev) :input #'read-interface)))

(defun tap-disable (dev)
  (system:invalidate-descriptor (tapdev-fd dev)))

(defun tap-destroy (dev)
  (close-tunnel (tapdev-fd dev)))

;;; 
;;; Packet-socket device driver:

(defmacro with-root-access (&body body)
  #+root `(root:as-superuser ,@body)
  #-root `(progn ,@body))

(defstruct (psocket-device (:include device)
                           (:print-function print-psocket-device))
  (name         (ext:required-argument) :type string)
  (fd           (ext:required-argument) :type integer)
  (interface-id (ext:required-argument) :type integer))

(defun make-packet-socket-device (name)
  "Make a packet-socket device attached to the host interface NAME.
Packet-socket (PF_PACKET) read and write ethernet frames directly on
one of the host's network interfaces, e.g. 'eth0'. Frames transmitted
are sent directly onto the network, making packet-socket devices
useful for communicating with other machines, but not with the Lisp's
host machine. [This may be a bug or misunderstanding in netlib.]

See the Linux packet(7) man page for details about packet-sockets."
  (multiple-value-bind (fd id)
      (with-root-access (packet-socket:open-packet-socket name))
    (make-psocket-device :tx-fun 'psocket-tx
                         :enable-fun 'psocket-enable
                         :disable-fun 'psocket-disable
                         :destroy-fun 'psocket-destroy
                         :name name
                         :fd fd
                         :interface-id id)))

(defun print-psocket-device (dev stream depth)
  (declare (ignore depth))
  (print-unreadable-object (dev stream :type t :identity t)
    (format stream "~S (FD:~S ID:~S)"
            (psocket-device-name dev)
            (psocket-device-fd dev)
            (psocket-device-interface-id dev))))

(defun psocket-tx (dev frame)
  (packet-socket:send (psocket-device-fd dev)
                      (psocket-device-interface-id dev) frame))

(defun psocket-rx (dev)
  (packet-socket:recv (psocket-device-fd dev)))

(defun psocket-enable (dev rx-fun)
  (flet ((read-interface (fd)
           (declare (ignore fd))
           (let ((input-frame (psocket-rx dev)))
             (when input-frame
               (funcall rx-fun input-frame)))))
    (system:add-fd-handler (psocket-device-fd dev) :input #'read-interface)))

(defun psocket-disable (dev)
  (system:invalidate-descriptor (psocket-device-fd dev)))

(defun psocket-destroy (dev)
  (unix:unix-close (psocket-device-fd dev)))

;;; 
;;; Packet decoding.

(eval-when (:compile-toplevel :load-toplevel)
  ;; This is a kludge to avoid a lot of compiler warnings.  Unless I
  ;; *print* each of these structures, I get a warning each time I try
  ;; to use SLOT-VALUE on structures of their types.
  ;;
  ;; So, I print them.
  (format nil "~S" (list (make-ethh)
                         (make-arph)
                         (make-iph)
                         (make-icmph)
                         (make-udph)
                         (make-tcph))))

;; Ethernet
(defun read-ethh (stream)
  "Read an ethernet header from STREAM."
  (funcall (binary-reader-fn ethh) stream))

;; ARP
(defun read-arph (stream)
  "Read an ARP header from STREAM."
  (funcall (binary-reader-fn arph) stream))

;; IPv4
(defun read-iph (stream)
  "Read an IPv4 header from STREAM."
  (let ((iph (funcall (binary-reader-fn iph) stream)))
    (when (iph-expects-options-p iph)
      (setf (iph-options iph) (read-iph-options stream)))
    iph))

(defun iph-expects-options-p (iph)
  "Return true if IPH will be followed by options."
  ;; base IP header with no options is 5 words
  (> (iph-hlen iph) 5))

(defun read-iph-options (stream)
  (let* ((option (read-byte stream))
	 (copied (ldb (byte 1 7) option))
	 (class  (ldb (byte 2 5) option))
	 (number (ldb (byte 5 0) option)))
    (declare (ignore copied))
    (ecase class
      (0				; control class
       (ecase number
	 (#.ipopt-end-of-options
	  '())
	 (#.ipopt-nop
	  (read-iph-options stream))
	 (#.ipopt-security
	  (acons :security (read-vector stream 11)
		 (read-iph-options stream)))
	 (#.ipopt-loose-source-routing
	  (acons :loose-source-routing (read-vector stream (read-byte stream))
		 (read-iph-options stream)))
	 (#.ipopt-strict-source-routing
	  (acons :strict-source-routing (read-vector stream (read-byte stream))
		 (read-iph-options stream)))
	 (#.ipopt-record-route
	  (acons :record-route (read-vector stream (read-byte stream))
		 (read-iph-options stream)))
	 (#.ipopt-stream-id
	  (acons :stream-id (read-vector stream 4)
		 (read-iph-options stream)))))
      (2				; debugging class
       (ecase number
	 (#.ipopt-timestamp 
	  (acons :timestamp (read-vector stream (read-byte stream))
		 (read-iph-options stream))))))))

;; ICMP
(defun read-icmph (stream)
  "Read an ICMP header from STREAM."
  (funcall (binary-reader-fn icmph) stream))

;; UDP
(defun read-udph (stream)
  "Read a UDP header, and packet data, from STREAM."
  (let ((udph (funcall (binary-reader-fn udph) stream)))
    (setf (udph-data udph)
          (read-vector (- (udph-length udph) 8) ; account for header
                       stream))
    udph))

;; TCP
(defun read-tcph (stream iph)
  "Read a TCP header from STREAM, using the IP header to fill in addresses."
  (let ((tcph (funcall (binary-reader-fn tcph) stream)))
    (setf (tcph-src-ip tcph) (iph-source iph))
    (setf (tcph-dest-ip tcph) (iph-dest iph))
    (when (tcph-has-options-p tcph)
      (with-binary-input-from-vector
          (opts-stream (read-vector (tcph-options-length tcph) stream))
        (setf (tcph-options tcph)
	      (tcp-read-options opts-stream))))
    ;; and the payload..
    (setf (tcph-data tcph)
	  (if (zerop (tcp-data-length iph tcph))
              nil
              (read-vector (tcp-data-length iph tcph) stream)))
    tcph))

(defun tcp-data-length (iph tcph)
  "Calculate the TCP payload size -- the total packet size minus the
  size of the IP and TCP headers (each specified words.)"
  (- (iph-total-len iph)
     (* 4 (iph-hlen iph))
     (* 4 (tcph-data-offset tcph))))

(defun tcp-read-options (stream)
  "Read TCP options from STREAM, and return them in an alist."
  (ecase (read-byte stream nil tcpopt-end-of-options)
    (#.tcpopt-end-of-options
     '())
    (#.tcpopt-nop
     (tcp-read-options stream))
    (#.tcpopt-mss
     (read-byte stream)			; length
     (acons :mss
	    (dpb (read-byte stream)
		 (byte 8 8)
		 (read-byte stream))
	    (tcp-read-options stream)))))


(defun tcph-has-options-p (tcph)
  (> (tcph-data-offset tcph) 5))

(defun tcph-options-length (tcph)
  (* 4 (- (tcph-data-offset tcph) 5)))

;; Utility

(defun read-vector (n stream)
  (read-binary (binary-vector 'u8 n) stream))

;;; 
;;; Packet encoding.

;; IO vectors

(defstruct iovec
  "An IO-vector is a list of simple-array vectors.
  It is an analog of the 'iovec' C structure used by the Unix readv(3)
  and writev(3) system calls."
  (vectors nil :type list))

(defun new-iovec (&rest vectors)
  (make-iovec :vectors (mapcar #'thing-to-vector vectors)))

(defun iovec-cons (x iovec)
  (make-iovec :vectors (cons (thing-to-vector x)
                             (iovec-vectors iovec))))

(defun thing-to-vector (x)
  (if (vectorp x)
      x
      (binary-to-vector x)))

(defun iovec-length (iov)
  (reduce #'+ (iovec-vectors iov) :key #'length))

(defun iovec-to-vector (iov)
  (apply #'concatenate '(vector (unsigned-byte 8)) (iovec-vectors iov)))

(defun binlist-to-vector (binlist)
  (apply #'concatenate
         '(vector (unsigned-byte 8))
         (mapcar #'binary-to-vector binlist)))

(defun-binary-writer ethh-to-vector ethh
  "Encode an ethernet header as a vector.")
(defun-binary-writer arph-to-vector arph
  "Encode an ARP header as a vector.")
(defun-binary-writer iph-to-vector iph
  "Encode an IP header as a vector.")
(defun-binary-writer icmph-to-vector icmph
  "Encode an ICMP header as a vector.")
(defun-binary-writer udph-to-vector udph
  "Encode a UDPH header as a vector.")
(defun-binary-writer tcph-to-vector tcph
  "Encode a TCPH header as a vector.")

(defun binary-to-vector (x)
  (typecase x
    (vector x)
    (ethh (ethh-to-vector x))
    (arph (arph-to-vector x))
    (iph  (iph-to-vector x))
    (udph (udph-to-vector x))
    (tcph (tcph-to-vector x))
    (t
     (with-binary-output-to-vector (s)
       (write-binary-record x s)))))

(defun concat-vectors (&rest vectors)
  "Concatenate VECTORS into a simple-array."
  (apply #'concatenate '(vector (unsigned-byte 8)) vectors))

;; Machinery

(defconstant iph-checksum-position 10
  "Byte offset of the checksum in IPv4 header.")

(defconstant icmp-checksum-position 2
  "Byte offset of the checksum in ICMP header.")

(defconstant tcph-checksum-position 16
  "Byte offset of the checksum in TCP header.")

(defun packet-to-frame (packet)
  "Encode PACKET into a binary frame.
  PACKET must be a sensible list of protocol headers, for example:
    (#<ETHH> #<ARPH)
    (#<ETHH> #<IPH> #<TCPH [include data]>)"
;  (declare (type packet packet))
  (assert (well-formed-packet-p packet))
  (let ((revpacket (reverse packet)))
    (etypecase (first revpacket)
      (tcph  (apply #'encode-tcp revpacket))
      (udph  (apply #'encode-udp revpacket))
      (icmph (apply #'encode-icmp revpacket))
      (arph  (apply #'encode-arp revpacket)))))

(defun encode-tcp (tcph iph ethh)
  (let ((frame (concatenate '(vector (unsigned-byte 8))
                            (binary-to-vector tcph)
                            (binary-to-vector (tcph-data tcph)))))
    (add-checksum! frame
                   tcph-checksum-position
                   (tcp-pseudo-header-checksum tcph iph frame))
    (encode-ip ip-protocol-tcp (new-iovec frame) iph ethh)))

(defun tcp-pseudo-header-checksum (tcph iph frame)
  (with-slots (src-ip dest-ip) tcph
    (checksum (binary-to-vector
	       (make-tcp-pseudo-iph :src-ip  (iph-source iph)
				    :dest-ip (iph-dest iph)
				    :proto ip-protocol-tcp
				    :len (length frame))))))

(defun encode-icmp (icmph iph ethh)
  (let ((vec (concat-vectors (binary-to-vector icmph) (icmph-data icmph))))
    (add-checksum! vec icmp-checksum-position)
    (encode-ip ip-protocol-icmp (new-iovec vec) iph ethh)))

(defun encode-udp (udph iph ethh)
  (encode-ip ip-protocol-udp (new-iovec udph) iph ethh))

(defun encode-arp (arph ethh)
  (encode-eth ethtype-arp (new-iovec arph) ethh))

(defun encode-ip (protocol iov iph ethh)
  (unless (iph-protocol iph)
    (setf (iph-protocol iph) protocol))
  (unless (iph-total-len iph)
    (setf (iph-total-len iph) (+ (* (iph-hlen iph) 4) (iovec-length iov))))
  (let ((header-vec (binary-to-vector iph)))
    (add-checksum! header-vec iph-checksum-position)
    (encode-eth ethtype-ip (iovec-cons header-vec iov) ethh)))

(defun encode-eth (type iov ethh)
  (unless (ethh-type ethh)
    (setf (ethh-type ethh) type))
  (iovec-to-vector (iovec-cons ethh iov)))

(defun well-formed-packet-p (packet)
  (typep packet 'packet))

(defun packet-type-signature (packet)
  (mapcar #'type-of packet))

;; Checksumming

(defun add-checksum! (frame pos &optional (initial 0))
  "Checksum FRAME and write the 16-bit result starting at POS, then
return the (destructively) updated frame."
  (let ((csum (compute-checksum frame initial)))
    (setf (aref frame pos)      (ldb (byte 8 8) csum))
    (setf (aref frame (1+ pos)) (ldb (byte 8 0) csum))
    frame))

(defun compute-checksum (s &optional (initial 0))
  "Compute the IP checksum of the header in vector S."
  (let* ((sum (checksum s initial))
	 (sum (+ (ldb (byte 16 16) sum) (ldb (byte 16 0) sum)))
	 (sum (+ sum (ldb (byte 16 16) sum))))
    (logxor #xFFFF (ldb (byte 16 0) sum))))

(defun checksum (s &optional (sum 0))
  (loop for i from 0 below (length s) by 2
        do (let ((msb (aref s i))
                 (lsb (if (= i (1- (length s)))
                          0
                          (aref s (1+ i)))))
             (incf sum (dpb msb (byte 8 8) lsb)))
        finally (return sum)))

