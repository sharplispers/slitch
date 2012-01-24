(defpackage "TUNTAP"
  (:use "COMMON-LISP" "UNIX" "ALIEN" "C-CALL")
  (:export "CREATE-TUNNEL" "CLOSE-TUNNEL" "TUNNEL-READ" "TUNNEL-WRITE"))

(in-package "TUNTAP")

;;; -----------------------------------------------------------
;;; System call interface type definitions (using CMUCL "Alien" FFI)

;; From <linux/if.h>

(defconstant +IFNAMSIZ+ 16)

;; Faked 16-byte type, just to pad the union in ifreq to the right size.
(def-alien-type ifru-pad
  (struct ifru-pad
  (pad (array char #.+IFNAMSIZ+))))

;; From <linux/if.h>
(def-alien-type ifreq
  (struct ifreq
	  (name (array char 16))
	  (ifru (union ifr-ifru
		       (flags short)
		       (dummy ifru-pad)))))

;; From <linux/if_tun.h>

(defconstant +IFF-TUN+       #x0001)
(defconstant +IFF-TAP+       #x0002)
(defconstant +IFF-NO-PI+     #x1000)
(defconstant +IFF-ONE-QUEUE+ #x2000)

(defconstant +TUNSETIFF+     #x400454ca)

;;; -----------------------------------------------------------
;;; Lisp interface

(defun create-tunnel (type &optional name)
  "Open a tunnel and return the file descriptor."
  (multiple-value-bind (fd err)
      (unix-open "/dev/net/tun" o_rdwr 0)
    (if fd
	(init-tunnel fd type name)
      (error "Failed to open tunnel: ~s" (get-unix-error-msg err)))))

(defun init-tunnel (fd type name)
  (let ((type-code (ecase type
		     (:tun +IFF-TUN+)
		     (:tap +IFF-TAP+))))
    (with-alien ((req (struct ifreq)))
      (if (null name)
          (setf (deref (slot req 'name) 0) 0)
          ;; yucksome.. copy name into ifreq's cstring
          (do ((idx 0 (1+ idx)))
              ((or (= idx (length name))
                   (= idx +IFNAMSIZ+))
               (setf (deref (slot req 'name) idx) 0))
            (setf (deref (slot req 'name) idx)
                  (char-code (aref name idx)))))
      (setf (slot (slot req 'ifru) 'flags)
	    (logior type-code +IFF-NO-PI+ +IFF-ONE-QUEUE+))
      (if (unix-ioctl fd +TUNSETIFF+ (alien-sap req))
	  fd
	  (error "TUNSETIFF ioctl failed")))))

(defun close-tunnel (fd)
  "Close the tunnel file descriptor, destroying the interface."
  (unix-close fd))

(defun tunnel-read (fd &optional
                    (buffer (make-array 2048
                                        :element-type '(unsigned-byte 8))))
  "Read a frame from a tunnel file descriptor.
The frame is returned as a vector of bytes."
  (system:wait-until-fd-usable fd :input)
  (system:without-gcing
   (let ((length (unix-read fd (system:vector-sap buffer) (length buffer))))
     (and length (adjust-array buffer (list length))))))

(defun tunnel-write (fd frame)
  "Write a frame to the tunnel.
The frame can either be a string or a vector of 8-bit integers."
  (declare (type simple-array frame))
  (unix-write-frame fd frame))

(defun unix-write-frame (fd vec)
  (unix-write fd vec 0 (length vec)))
