(defpackage :packet-socket
  (:use :common-lisp :unix :alien :c-call)
  (:export :open-packet-socket :send :recv))

(in-package :packet-socket)

;; From <linux/if.h>, tuntap,lisp

(defconstant IFNAMSIZ  16)
(defconstant PF_PACKET 17)
(defconstant SOCK_RAW  3)
(defconstant ETH_P_ALL #.(ext:htons 3))
(defconstant SIOCGIFINDEX #x8933)
(defconstant PACKET_ADD_MEMBERSHIP 1)
(defconstant SOL_PACKET 263)
(defconstant PACKET_MR_PROMISC 1)
(defconstant PACKET_OUTGOING 0)

;; Faked 16-byte type, just to pad the union in ifreq to the right size.
(def-alien-type ifru-pad
  (struct ifru-pad
  (pad (array char #.IFNAMSIZ))))

;; From <linux/if.h>
(def-alien-type ifreq
  (struct ifreq
	  (name (array char 16))
	  (ifru (union ifr-ifru
		       (flags short)
                       (ivalue int)
		       (dummy ifru-pad)))))

;; From <linux/if_packet.h>
(def-alien-type packet-mreq
    (struct packet-mreq
            (ifindex int)
            (type short)
            (alen short)
            (address (array char 8))))

(def-alien-type sockaddr-ll
    (struct socketaddr-ll
            (family unsigned-short)
            (protocol unsigned-short)
            (ifindex int)
            (hatype unsigned-short)
            (pkttype unsigned-char)
            (halen unsigned-char)
            (addr (array unsigned-char 8))))

(def-alien-routine ("memset" memset) void
  (s (* t)) (c int) (n int))

(def-alien-routine ("memcpy" memcpy) void
  (dest (* t)) (src (* t)) (n int))

(defun open-packet-socket (interface-name)
  (let ((socket-fd (unix:unix-socket PF_PACKET SOCK_RAW ETH_P_ALL)))
    (when (= socket-fd -1)
      (error "socket(2) call failed for packet socket. (Are we root?)"))
    (let ((interface-id (get-interface-id socket-fd interface-name)))
      (bind socket-fd interface-id)
      (values socket-fd interface-id))))

(defun bind (socket-fd interface-index)
  (with-alien ((addr sockaddr-ll))
    (let ((*addr (alien-sap addr))
          (size (alien-size sockaddr-ll :bytes)))
      (setf (slot addr 'family) PF_PACKET)
      (setf (slot addr 'protocol) ETH_P_ALL)
      (setf (slot addr 'ifindex) interface-index)
      (unless (zerop (unix:unix-bind socket-fd *addr size))
        (error "BIND failed!")))))

(defun get-interface-id (socket-fd name)
  (with-alien ((req (struct ifreq)))
    ;; yucksome.. copy name into ifreq's cstring
    (do ((idx 0 (1+ idx)))
        ((or (= idx (length name))
             (= idx IFNAMSIZ))
         (setf (deref (slot req 'name) idx) 0))
      (setf (deref (slot req 'name) idx)
            (char-code (aref name idx))))
    (if (unix:unix-ioctl socket-fd SIOCGIFINDEX (alien-sap req))
        (slot (slot req 'ifru) 'ivalue)
        (error "SIOCGIFINDEX for ~S failed!" name))))

(defun send (socket-fd interface-id frame)
  (declare (type simple-array frame))
  (system:without-gcing
   (with-alien ((addr sockaddr-ll))
     (let ((size (alien-size sockaddr-ll :bytes)))
       (memset (addr addr) 0 size)
       (setf (slot addr 'family) PF_PACKET)
       (setf (slot addr 'ifindex) interface-id)
;;       (setf (slot addr 'pkttype) PACKET_OUTGOING)
       (setf (slot addr 'halen) 6)
       ;; Copy DMAC
       (memcpy (system:sap+ (alien-sap addr) 12) (system:vector-sap frame) 6)
       #+nil
       (dotimes (i 8)
         (setf (aref (slot addr 'addr) i) 255))
       (sendto socket-fd (system:vector-sap frame) (length frame) 0
               (addr addr) size)))))

(defun recv (socket-fd &optional
             (buffer (make-array 2048
                                 :element-type '(unsigned-byte 8))))
  (system:wait-until-fd-usable socket-fd :input)
  (system:without-gcing
   (let ((length (unix:unix-recv socket-fd
                                 buffer
                                 (length buffer)
                                 0)))
     (when (plusp length)
       (and length (adjust-array buffer (list length)))))))


(def-alien-routine ("sendto" sendto) int
  (fd int)
  (buffer (* char))
  (length int)
  (flags int)
  (sockaddr-ll (* t))
  (len int))
