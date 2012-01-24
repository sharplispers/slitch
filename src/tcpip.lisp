;;; switch.lisp -- top level "switching" code

(defpackage :tcpip
  (:use :common-lisp :netlib :window :binary-types)
  (:export :start :routes :netstat))

(in-package :tcpip)

;;; Protocol stack overview.
;;
;; The name "protocol stack" suggests a set of protocols stacked on
;; top of one another. That's just how a TCP/IP stack is organised --
;; as layers of protocols, each building on the ones below. The
;; protocols currently supported are stacked like this:
;;
;; +------------------+
;; | ICMP | UDP | TCP |_____+
;; | IPv4             | ARP |
;; | Ethernet               |
;; | Physical network       |
;; +------------------------+
;;
;; Here's how it works:
;;
;; When a packet arrives from the network, it is converted into a
;; stream. The stream is then passed up the protocol stack, starting
;; with ethernet, until a layer is reached that knows what to do with
;; it.
;;
;; Output works the other way: it begins in a high level protocol
;; layer, and has to make its way down the stack to the network. The
;; packet is represented as a list of protocol header structures, to
;; which each layer prepends its own on the way through. For example,
;; when a TCP packet reaches the network layer it will look something
;; like this:
;;
;;   (#<ETHH> #<IPH> #<TCPH [including data]>)
;;
;; The network layer then converts this into a binary frame and sends
;; it into the world.
;;
;; Most of the mappings between structures and binary data is handled
;; by the BINARY-TYPES package. The binary-structure definitions
;; describing protocol headers can be found in `switch-types.lisp'.

;;; Top level

;; Some global variables that probably ought to be eliminated.
(defvar *mac-address* nil
  "During packet processing, the MAC address of the input interface.")
(defvar *ip-address* nil
  "During packet processing, the IP address of the input interface.")
(defvar *input-interface* nil
  "During packet processing, bound to the interface the packet arrived on.")

;;; Main entry point

(defun start ()
  "Initialize a network interface and start handling traffic."
  (let ((iface (make-tap-interface "lisp0")))
;  (let ((iface (make-packet-socket-interface "eth0")))
    (ifconfig-address iface @192.168.43.10)
    (enable-interface iface)
    ;; Use 192.168.43.1 as default gateway
    (add-route (make-net-route @0.0.0.0 @0.0.0.0 iface @192.168.43.1))
    iface))

;;; Utilities

(defvar *switch-trace* nil
  "When non-nil, print trace information as packets are processed.")

(defun debug-print (fmt &rest args)
  (when *switch-trace*
    (format *trace-output* "~&~?~%" fmt args)))

;;; Network interfaces

(defvar *interfaces* ()
  "List of existing interfaces.")

(defstruct (interface (:print-function print-interface)
                      (:constructor %make-interface))
  (name            (ext:required-argument) :type string)
  (type            (ext:required-argument) :type symbol)
  (ip              nil :type (or null ip-addr))
  (netmask         nil :type (or null ip-addr))
  (broadcast-ip    nil :type (or null ip-addr))
  (network-ip      nil :type (or null ip-addr))
  (bytes-in        0   :type integer)
  (bytes-out       0   :type integer)
  (up?             nil :type (member t nil))
  (mac             (ext:required-argument) :type mac-addr)
  (dev             (ext:required-argument) :type device))

(defun print-interface (iface stream depth)
  (declare (ignore depth))
  (let ((ip (interface-ip iface))
        (nm (interface-netmask iface)))
    (print-unreadable-object (iface stream :type t :identity t)
      (format stream "~A: ~A/~A~A (~A)"
              (interface-name iface)
              (if ip (ip-addr-to-string ip) "0.0.0.0")
              (if nm (netmask-to-prefix-bits nm) "0")
              (if (interface-up? iface) "" " (DOWN)")
              (symbol-name (interface-type iface))))))


(defun make-interface (name type device &optional (mac (random-mac-addr)))
  "Create a new network interface, called NAME (a string).
TYPE is an object describing the type of interface; FD is a unix file
descriptor for use with SERVE-EVENT; RX-FUN and TX-FUN are functions
which are called to read and write frames."
  (when (find-interface name)
    (cerror "Replace interface ~S" "Interface ~S already exists" name)
    (delete-interface (find-interface name)))
  (let ((iface (%make-interface :name name
                                :type type
                                :dev device
                                :mac mac)))
    (setq *interfaces* (append *interfaces* (list iface)))
    iface))

(defun enable-interface (iface)
  "Enable traffic processing for INTERFACE."
  (unless (interface-up? iface)
    (setf (interface-up? iface) t)
    (let ((dev (interface-dev iface)))
      (enable-device dev (lambda (frame) (network-input iface frame)))
      t)))

(defun disable-interface (iface)
  "Disable traffic processing for INTERFACE."
  (when (interface-up? iface)
    (setf (interface-up? iface) nil)
    (let ((dev (interface-dev iface)))
      (disable-device dev)
      t)))

(defun delete-interface (iface)
  "Delete INTERFACE permanently."
  (disable-interface iface)
  (let ((dev (interface-dev iface)))
    (destroy-device dev))
  (setq *interfaces* (remove iface *interfaces*))
  t)

(defun find-interface (x)
  "Find an interface by name.
If X is a string, the interface whose name matches is found (or NIL if
there is no such interface.)
If X is already an interface, it is returned unchanged."
  (etypecase x
    (interface x)
    (string    (find x *interfaces* :key #'interface-name :test #'string=))))

(defun make-tap-interface (name)
  (make-interface name :tap (make-tap-device name)))

(defun make-packet-socket-interface (name)
  (make-interface name :p/socket
                  (root:as-superuser (make-packet-socket-device name))))

;;; Physical layer

(defun network-input (iface frame)
  "Accept and process a frame from a network interface."
  (declare (type simple-array frame))
  (incf (interface-bytes-in iface) (length frame))
  ;; Setup binary-types endianness for all processing
  (let ((*endian* :big-endian)
        (*input-interface* iface)
        (*ip-address* (interface-ip iface))
        (*mac-address* (interface-mac iface)))
    (with-binary-input-from-vector (stream frame)
      (ethernet-input stream iface))))

(defun network-output (binlist iface)
  "Write BINLIST (a list of binary-records) to a network interface."
  (let ((frame (packet-to-frame binlist)))
    (incf (interface-bytes-out iface) (length frame))
    (let ((dev (interface-dev iface)))
      (transmit dev frame))))

;;; Ethernet layer

(defun ethernet-input (stream iface)
  (let* ((ethh (read-ethh stream)))
    (when (eth-for-me? ethh iface)
      (case (ethh-type ethh)
        (#.ethtype-arp (arp-input stream iface))
        (#.ethtype-ip  (ip-input stream))
        (otherwise
         (debug-print "Unrecognised frame type: #x~16,2,'0R"
                      (ethh-type ethh)))))))

(defun eth-for-me? (ethh iface)
  (or (equalp (ethh-dest ethh) (interface-mac iface))
      (equalp (ethh-dest ethh) broadcast-mac)))

(defun ethernet-output (iolist type dest iface)
  (network-output (cons (make-ethh :dest dest
				   :src (interface-mac iface)
				   :type type)
			iolist)
                  iface))

;;; ARP

(defvar *arp-cache* (make-hash-table :test #'equalp)
  "ARP cache, mapping IP addresses onto MAC addresses.")

(defun arp-input (stream iface)
  (let ((frame (read-arph stream)))
    ;; For now, populate ARP cache with all addresses we see, not just
    ;; those directly concerning ourselves. This should ease our pain
    ;; until we implement sending ARPs.
    (arp-cache-add (arph-sender-ip frame) (arph-sender-ha frame))
    (if (arp-for-me? frame iface)
	(arp-reply frame iface)
	(debug-print "ARP not for me"))))

(defun arp-reply (req iface)
  (declare (type arph req))
  (debug-print "Replying to ARP from ~A (~A)"
	       (ip-addr-to-string (arph-sender-ip req))
	       (mac-addr-to-string (arph-sender-ha req)))
  (let ((resp (copy-structure req)))
    ;; Using the request as a template, create the response
    (setf (arph-operation resp) arp-operation-response)
    (setf (arph-target-ha resp) (arph-sender-ha req))
    (setf (arph-target-ip resp) (arph-sender-ip req))
    (setf (arph-sender-ha resp) (interface-mac iface))
    (setf (arph-sender-ip resp) (interface-ip iface))
    (ethernet-output (list resp)
                     ethtype-arp
                     (arph-target-ha resp)
                     iface)))

(defun arp-cache-add (ip mac)
  "Record the MAC address for IP in the arp cache."
  (setf (gethash ip *arp-cache*) mac))

(defun arp-cache-lookup (ip)
  "Lookup the MAC address for IP from the arp cache."
  (gethash ip *arp-cache*))

(defun arp-for-me? (arp iface)
  (and (equalp (arph-operation arp) arp-operation-request)
       (equalp (arph-target-ip arp) (interface-ip iface))))

;;; IPv4 (Routing)

(defvar *routes* ()
  "Routing table.
Contains all routes, sorted from most- to least- specific network mask.")

(defstruct (route (:print-function pprint-route)
                  (:constructor
                   %make-route (destination netmask gateway interface)))
  (destination nil :type ip-addr)
  (netmask     nil :type ip-addr)
  (gateway     nil :type (or null ip-addr))
  (interface   nil :type interface))

(defun pprint-route (route stream depth)
  "Pretty-print a route structure."
  (declare (ignore depth))
  (print-unreadable-object (route stream :type t)
    (format stream "~A/~A dev ~A"
            (ip-addr-to-string (route-destination route))
            (netmask-to-prefix-bits (route-netmask route))
            (interface-name (route-interface route)))
    (when (route-gateway route)
      (format stream " via ~A" (ip-addr-to-string (route-gateway route))))))

(defun make-host-route (host iface)
  "Make a route to a single host."
  (%make-route host @255.255.255.255 nil (find-interface iface)))

(defun make-net-route (net mask iface &optional gateway)
  "Make a route to a network."
  (%make-route net (as-netmask mask) gateway (find-interface iface)))

(defun add-route (route)
  "Add a route to the routing table."
  (setq *routes*
        (merge 'list *routes* (list route) #'ip>= :key #'route-netmask)))

(defun lookup-route (ip)
  "Return the route to IP, or NIL if none is known."
  (find-if (lambda (route) (route-includes-p route ip))
           *routes*))

(defun route-includes-p (route ip)
  "Return true if ROUTE can be used to reach IP."
  (equalp (route-destination route)
          (mask-ip ip (route-netmask route))))

;;; IPv4 (Engine)

(defvar *ip-allow-forwarding* t
  "Non-nil means IP packets arriving for other destinations will be routed.")

;; Input

(defun ip-input (stream)
  "Process the IP packet contained in STREAM."
  (let ((iph (read-iph stream)))
    (if (ip-local-destination-p iph)
        (ip-local-input iph stream)
        #+nil (when *ip-allow-forwarding* (ip-forward iph stream)))))

(defun ip-local-input (iph stream)
  "Input an IP packet which has been sent to a local interface."
  (case (iph-protocol iph)
    (#.ip-protocol-icmp (icmp-input iph stream))
    (#.ip-protocol-udp  (udp-input iph stream))
    (#.ip-protocol-tcp  (tcp-input iph stream))
    (otherwise
     (debug-print "Unrecognised IP protocol: #x~16,2,'0R"
                  (iph-protocol iph)))))

(defun ip-local-destination-p (iph)
  "Return true if IPH's destination matches a local interface."
  ;; FIXME: should check all interfaces
  (or (equalp (iph-dest iph) (interface-ip *input-interface*))
      (equalp (iph-dest iph) (interface-broadcast-ip *input-interface*))))

;; Output

;; FIXME! Need a way to output partially-encoded/decoded frames, or to
;; fully decode them before forwarding.
#+nil
(defun ip-forward (iph stream)
  "Forward an IP packet that is destined for another host."
  (unless (<= (iph-ttl iph) 1)          ; FIXME: ICMP
    (multiple-value-bind (iface dest) (ip-route (iph-dest iph))
      (unless (null iface)
        (decf (iph-ttl iph))
        ;; HACK: null out any fields that we can't encode
        (setf (iph-options iph) ())
        (decf (iph-total-len iph) (* 4 (- (iph-hlen iph) 5)))
        (setf (iph-checksum iph) 0)
        (let* ((body (read-vector (- (iph-total-len iph)
                                     (* 4 (iph-hlen iph)))
                                  stream)))
          (ip-xmit (cons iph body) dest iface))))))

(defun ip-output (dest protocol body)
  (multiple-value-bind (interface destination) (ip-route dest)
    (when interface
      (let* ((iph (make-iph :version 4
                            :hlen 5
                            :tos 0
                            :id 0
                            :flags 0
                            :fragment-offset 0
                            :ttl 64
                            :protocol protocol
                            :checksum 0
                            :source (interface-ip interface)
                            :dest dest
                            :options '())))
        (ip-xmit (cons iph body) destination interface)))))

(defun ip-route (dest)
  "Lookup the route to DEST (an IP address.)
  On success, returns two values: the output interface, and the next-hop
  IP address.
  On failure, returns NIL."
  (let ((route (lookup-route dest)))
    (cond ((null route)
           (debug-print "No route for ~A" dest)
           nil)
          ((route-gateway route)
           (values (route-interface route)
                   (route-gateway route)))
          (t
           (values (route-interface route)
                   dest)))))

(defun ip-xmit (packet dest iface)
  (if (arp-cache-lookup dest)         ; FIXME: per-interface ARP cache
      (ethernet-output packet
                       ethtype-ip
                       (arp-cache-lookup dest)
                       iface)
      (debug-print "Can't send to ~A -- don't know MAC address" dest)))

;;; ICMP

(defun icmp-input (iph stream)
  (let ((frame (read-icmph stream)))
    (case (icmph-type frame)
      (#.icmp-type-echo-request (icmp-echo-request iph stream))
      (otherwise
       (debug-print "Got unrecognised ICMP packet: ~A" frame)))))

(defun icmp-echo-request (iph stream)
  (let* ((id (read-binary 'u16 stream))
	 (seq (read-binary 'u16 stream))
	 (bodylen (- (iph-total-len iph) (* (iph-hlen iph) 4) 8))
	 (data (binary-input-remainder stream bodylen))
          #+nil
          (read-vector bodylen stream))
    (debug-print "Got PING")
    (let* ((body (with-binary-output-to-vector (out)
                   (write-binary 'u16 out id)
                   (write-binary 'u16 out seq)
                   (loop for ch across data
                         do
                         (funcall binary-types::*binary-write-byte*
                                     ch out)
                         #+nil
                         (write-binary 'u8 out ch)))))
      (icmp-output icmp-type-echo-reply (iph-source iph) body))))

(defun icmp-output (type dest data)
  (let ((icmph (make-icmph :type type)))
    (setf (icmph-data icmph) data)
    (ip-output dest ip-protocol-icmp (list icmph))))

(defun binary-input-remainder (stream &optional size)
  "Get the remainder of the binary input stream as a vector.
This has unspecified destructive effects on both the stream and the
vector it reads from."
  (multiple-value-bind (vec pos) (binary-vector-input-state stream)
    (let ((dimensions (list (or size (- (length vec) pos)))))
      (adjust-array (make-array dimensions
                                :element-type '(unsigned-byte 8))
                    dimensions
                    :displaced-to vec
                    :displaced-index-offset pos))))
  
;;; UDP

;; Handler registry

(defvar *udp-port-handlers* (make-hash-table)
  "Hash table from UDP port to handler function.
The handler is called with two arguments: the UDP packet structure,
and the interface it arrived on.")

(defun set-udp-port-handler (port function &optional (force-p nil))
  (unless (or (null (gethash port *udp-port-handlers*))
              force-p)
    (cerror "Replace existing handler"
            "Port ~S is already handled by ~S"
            port (gethash port *udp-port-handlers*)))
  (setf (gethash port *udp-port-handlers*) function))

(defun remove-udp-port-handler (port)
  (remhash port *udp-port-handlers*))

;; Packet handling

(defun udp-input (iph stream)
  (declare (ignore iph))
  (let ((udph (read-udph stream)))
    (let ((handler (gethash (udph-dest-port udph) *udp-port-handlers*)))
      (if handler
          (funcall handler udph *input-interface*)
          ;; FIXME: send ICMP port-unreachable
          ))))

(defun udp-output (source-port dest-ip dest-port data
                   &optional (checksum-p nil))
  (let* ((udph (make-udph :src-port source-port
                          :dest-port dest-port
                          :length (+ (length data) 8)
                          :checksum 0
                          :data data)))
    (ip-output dest-ip ip-protocol-udp (list udph))))

;;; TCP

;; ======================================================================
;; TCP layer
;;
;;                       TCP Connection State Diagram
;;
;;                               +---------+ ---------\      active OPEN  
;;                               |  CLOSED |            \    -----------  
;;                               +---------+<---------\   \   create TCB  
;;                                 |     ^              \   \  snd SYN    
;;                    passive OPEN |     |   CLOSE        \   \           
;;                    ------------ |     | ----------       \   \         
;;                     create TCB  |     | delete TCB         \   \       
;;                                 V     |                      \   \     
;;                               +---------+            CLOSE    |    \   
;;                               |  LISTEN |          ---------- |     |  
;;                               +---------+          delete TCB |     |  
;;                    rcv SYN      |     |     SEND              |     |  
;;                   -----------   |     |    -------            |     V  
;;  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
;;  |         |<-----------------           ------------------>|         |
;;  |   SYN   |                    rcv SYN                     |   SYN   |
;;  |   RCVD  |<-----------------------------------------------|   SENT  |
;;  |         |                    snd ACK                     |         |
;;  |         |------------------           -------------------|         |
;;  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
;;    |           --------------   |     |   -----------                  
;;    |                  x         |     |     snd ACK                    
;;    |                            V     V                                
;;    |  CLOSE                   +---------+                              
;;    | -------                  |  ESTAB  |                              
;;    | snd FIN                  +---------+                              
;;    |                   CLOSE    |     |    rcv FIN                     
;;    V                  -------   |     |    -------                     
;;  +---------+          snd FIN  /       \   snd ACK          +---------+
;;  |  FIN    |<-----------------           ------------------>|  CLOSE  |
;;  | WAIT-1  |------------------                              |   WAIT  |
;;  +---------+          rcv FIN  \                            +---------+
;;    | rcv ACK of FIN   -------   |                            CLOSE  |  
;;    | --------------   snd ACK   |                           ------- |  
;;    V        x                   V                           snd FIN V  
;;  +---------+                  +---------+                   +---------+
;;  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
;;  +---------+                  +---------+                   +---------+
;;    |                rcv ACK of FIN |                 rcv ACK of FIN |  
;;    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |  
;;    |  -------              x       V    ------------        x       V  
;;     \ snd ACK                 +---------+delete TCB         +---------+
;;      ------------------------>|TIME WAIT|------------------>| CLOSED  |
;;                               +---------+                   +---------+
;;

(defconstant tcp-window-size 100)

(defvar *tcb-connection-table* (make-hash-table :test #'equalp)
  "Table of TCP Control Blocks (TCBs) of connections, indexed by a
  stream-id.")

(defvar *tcb-listen-table* (make-hash-table :test #'equalp)
  "Table of TCBs for LISTEN-ing sockets, mapping PORT -> TCB.")

(defvar tcp-low-dynamic-port  32768)
(defvar tcp-high-dynamic-port 65535)
(defvar tcp-next-dynamic-port tcp-low-dynamic-port)

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

(defun tcp-next-dynamic-port ()
  (prog1 tcp-next-dynamic-port
    (incf tcp-next-dynamic-port)
    (when (>= tcp-next-dynamic-port tcp-high-dynamic-port)
      (setf tcp-next-dynamic-port tcp-low-dynamic-port))))

(defstruct tcb
  "TCP Control Block: representing the state of one TCP connection."
  ;; Sending state (from RFC)
  snd.una snd.nxt snd.wnd snd.up snd.wl1 snd.wl2 iss
  ;; Receiving state (from RFC)
  rcv.wnd rc.up irs
  ;; internals
  rwin ;; receive window
  swin ;; send window
  fin-seq ;; sequence number of received FIN
  rdone ;; finished receiving (got FIN and all data)
  id ;; tcp-id endpoint pair
  state ;; state name (symbol)
  )

(defun tcp-input (iph stream)
  "Accept and process a TCP packet from STREAM."
  (let* ((tcph (read-tcph stream iph))
	 (id (input-packet-stream-id tcph))
	 (tcb (lookup-tcb id)))
    (cond ((tcb-p tcb)
	   (case (tcb-state tcb)
	     (syn-recv    (tcp-syn-recv-state tcb tcph))
             (syn-sent    (tcp-syn-sent-state tcb tcph))
	     (listen      (tcp-listen-state tcb tcph))
	     (established (tcp-established-state tcb tcph))
             (last-ack    (tcp-last-ack-state tcb tcph))
	     (otherwise (debug-print "Got packet for active TCB: ~S" tcb))))
	  (t
           (tcp-maybe-reset tcph)
	   (debug-print "Got stray packet; sent RST")))))

(defun lookup-tcb (id)
  "Lookup the TCP Control Block for the stream matching ID."
  (or (gethash id *tcb-connection-table*)
      (and (equalp (tcp-stream-id-local-ip id) *ip-address*)
	   (gethash (tcp-stream-id-local-port id) *tcb-listen-table*))))

(defun input-packet-stream-id (tcph)
  "The stream-id of a packet we received."
  (declare (type tcph tcph))
  (make-tcp-stream-id (tcph-dest-ip tcph) (tcph-dest-port tcph)
                      (tcph-src-ip tcph)  (tcph-src-port tcph)))

(defun first-syn? (tcph)
  (and (tcph-syn? tcph)
       (not (tcph-ack? tcph))))

(defun tcp-change-state (tcb state)
  (debug-print "STATE: ~A -> ~A (~A)" (tcb-state tcb) state (tcb-id tcb))
  (setf (tcb-state tcb) state))

;; ------------------------------------------------------------
;; LISTEN state

(defun tcp-listen-state (tcb tcph)
  "LISTEN state: create a new TCB for the connection, and send a
  SYN+ACK."
  (declare (ignore tcb))
  (cond ((tcph-rst? tcph))
	((and (tcph-syn? tcph) (not (tcph-ack? tcph)))
	 (let* ((iss (random (expt 2 32)))
                (irs (tcph-seq tcph))
                (id (input-packet-stream-id tcph))
		(new-tcb (make-tcb :state   'syn-recv
				   :irs     irs
				   :iss     iss
				   :snd.nxt (1+ iss)
				   :id      id
                                   :rwin    (make-window tcp-window-size
                                                         (1+ irs))
                                   :swin    (make-window tcp-window-size
                                                         (1+ iss)))))	
           (setf (gethash id *tcb-connection-table*) new-tcb)
	   (tcp-send-synack new-tcb)))
	(t
	 (tcp-send-reset tcph))))

;; ------------------------------------------------------------
;; SYN-RECEIVED state

(defun tcp-syn-recv-state (tcb tcph)
  (cond ((tcph-rst? tcph)
	 (tcp-dealloc tcb))
	((tcph-syn? tcph)
	 (tcp-dealloc tcb)
	 (tcp-send-reset tcph))
	(t
	 (tcp-change-state tcb 'established))))

;; ------------------------------------------------------------
;; SYN-SENT state

(defun tcp-syn-sent-state (tcb tcph)
  (cond ((tcph-has-flags tcph :rst)
         (tcp-dealloc  tcb))
        ((/= (tcph-ack-seq tcph) (1+ (tcb-iss tcb)))
         (tcp-dealloc tcb)
         (tcp-send-reset tcph))
        ((tcph-has-flags tcph :syn :ack)
         (setf (tcb-irs tcb) (tcph-seq tcph))
         (setf (window-start (tcb-rwin tcb)) (1+ (tcb-irs tcb)))
         (incf (tcb-snd.nxt tcb))
         (tcp-change-state tcb 'established)
         (tcp-transmit tcb nil :ack-seq (1+ (tcb-irs tcb)) :ack t))
        ((tcph-has-flags tcph :syn)
         (error "FIXME: Received SYN without ACK in SYN-SENT state."))))

(defun tcph-has-flags (tcph &rest flags)
  (or (null flags)
      (and (ecase (car flags)
             (:urg (tcph-urg? tcph)) (:ack (tcph-ack? tcph))
             (:psh (tcph-psh? tcph)) (:rst (tcph-rst? tcph))
             (:syn (tcph-syn? tcph)) (:fin (tcph-fin? tcph)))
           (apply #'tcph-has-flags tcph (cdr flags)))))

;; ------------------------------------------------------------
;; ESTABLISHED state

(defun tcp-established-state (tcb tcph)
  (cond ((tcph-rst? tcph)
         (tcp-dealloc tcb))
        ((tcph-syn? tcph)
         (tcp-send-reset tcph)
         (tcp-dealloc tcb))
        (t
         (tcpdata tcb tcph)
         (when (tcb-rdone tcb)
           ;; shortcut past CLOSE-WAIT into LAST-ACK by sending our FIN
           (tcp-transmit tcb nil :fin t :ack t)
           (tcp-change-state tcb 'last-ack)))))

;; ------------------------------------------------------------
;; LAST-ACK state

(defun tcp-last-ack-state (tcb tcph)
  (cond ((tcph-rst? tcph)
         (tcp-dealloc tcb))
        ((tcph-syn? tcph)
         (tcp-send-reset tcph)
         (tcp-dealloc tcb))
        ((tcph-ack? tcph)
         ;; all done! (though really we should check the ack-seq)
         (tcp-dealloc tcb))))

(defun tcpdata (tcb tcph)
  (when (tcph-data tcph)
    (debug-print "Got ~A in TCP" (tcph-data tcph))
    (window-write (tcb-rwin tcb)
                  (tcph-seq tcph)
                  (tcph-data tcph)))
  (when (tcph-fin? tcph)
    (setf (tcb-fin-seq tcb) (tcph-seq tcph))
    (setf (tcb-rdone tcb) t))
  (tcp-send-ack tcb))

;; ----------------------------------------------------------------------
;; Managing TCBs

(defun tcp-dealloc (tcb)
  (tcp-change-state tcb 'closed)
  (remhash (tcb-id tcb) *tcb-connection-table*))

(defun tcb-alloc ()
  (let ((iss (random (expt 2 32))))
    (make-tcb :state 'closed
              :iss iss
              :snd.nxt iss
              :rwin (make-window tcp-window-size 0)
              :swin (make-window tcp-window-size (1+ iss)))))

(defun tcb-bind (tcb local-ip local-port remote-ip remote-port)
  "Bind a TCB to a pair of endpoints."
  (let ((id (make-tcp-stream-id local-ip local-port remote-ip remote-port)))
    (setf (tcb-id tcb) id)
    (setf (gethash id *tcb-connection-table*) tcb)))

;; ----------------------------------------------------------------------
;; Transmission

(defun tcp-send-ack (tcb)
  (tcp-transmit tcb nil :ack t))

(defun tcp-send-synack (tcb)
  (tcp-transmit tcb nil :syn t :ack t)
  (incf (tcb-snd.nxt tcb)))

(defun tcp-send-data (tcb data)
  (tcp-transmit tcb data :ack t)
  (incf (tcb-snd.nxt tcb) (length data)))

(defun tcp-maybe-reset (tcph)
  "Send a RST in reply the packet TCPH, unless it was a RST itself."
  (unless (tcph-rst? tcph)
    (tcp-send-reset tcph)))

(defun tcp-send-reset (tcph)
  (tcp-output (make-tcph :src-ip (tcph-dest-ip tcph)
                         :dest-ip (tcph-src-ip tcph)
                         :src-port (tcph-dest-port tcph)
                         :dest-port (tcph-src-port tcph)
                         :data-offset 5	; hack
                         :seq (if (tcph-ack? tcph) ; Comer
                                  (tcph-seq tcph)
                                  0)
                         :ack-seq (+ (tcph-seq tcph) (tcp-datalen tcph))
                         :window 0
                         :rst? t
                         :ack? (not (tcph-ack? tcph))) ; Comer
              ""))

(defun tcp-datalen (tcph)
  (+ (if (or (tcph-syn? tcph) (tcph-fin? tcph)) 1 0)
     0)) ;; FIXME: packet length

(defun tcp-transmit (tcb data &rest keys)
  (let ((*endian* :big-endian))
    (tcp-output (apply #'make-output-tcph tcb keys)
                (or data ""))))

(defun make-output-tcph (tcb
                         &key src-ip dest-ip src-port dest-port
                         seq ack-seq data-offset
                         urg ack psh rst syn fin
                         window)
  (let ((id (tcb-id tcb)))
    (make-tcph :src-ip (or src-ip (tcp-stream-id-local-ip id))
               :dest-ip (or dest-ip (tcp-stream-id-remote-ip id))
               :src-port (or src-port (tcp-stream-id-local-port id))
               :dest-port (or dest-port (tcp-stream-id-remote-port id))
               :seq (or seq (tcb-snd.nxt tcb))
               :ack-seq (or ack-seq
                            ;; account for FIN
                            (let ((aseq (window-filled-pos (tcb-rwin tcb))))
                              (if (and (tcb-fin-seq tcb)
                                       (= (tcb-fin-seq tcb) aseq))
                                  (1+ aseq)
                                  aseq)))
               :data-offset (or data-offset 5) ; Hard-coded: no options
               :urg? urg :ack? ack :psh? psh :rst? rst :syn? syn :fin? fin
               :window (or window (- (window-end (tcb-rwin tcb))
                                     (window-filled-pos (tcb-rwin tcb)))))))

(defun tcp-output (tcph data)
  (setf (tcph-data tcph) data)
  (ip-output (tcph-dest-ip tcph) ip-protocol-tcp (list tcph)))

(defun tcp-connect (host port)
  (let ((tcb (tcb-alloc)))
    (tcb-bind tcb *ip-address* (tcp-next-dynamic-port) host port)
    (tcp-transmit tcb nil :syn t :ack-seq (tcb-iss tcb))
    (tcp-change-state tcb 'syn-sent)
    t))

;; Reading

(defun tcp-read-sockets ()
  (maphash (lambda (id tcb) (tcp-read id tcb))
           *tcb-connection-table*))

(defun tcp-read (id tcb)
  (declare (ignore id))
  (let* ((rwin (tcb-rwin tcb))
         (avail (- (window-filled-pos rwin) (window-start rwin)))
         (was-full-p (window-full-p rwin)))
    (when (> avail 0)
      (let ((data (window-read rwin avail)))
        (princ data)
        (window-advance rwin avail)
        (when was-full-p
          ;; opening up a zero window
          (let ((*endian* :big-endian))
            (tcp-send-ack tcb)))))))

;; Diagnostics

(defun tcp-reset ()
  (clrhash *tcb-connection-table*)
  (clrhash *tcb-listen-table*))

(defun tcp-listen (port)
  (setf (gethash port *tcb-listen-table*)
	(make-tcb :state 'listen)))

(defun show-tcp-connections ()
  (maphash #'show-tcp-connection
           *tcb-connection-table*)
  (values))

(defun show-tcp-connection (id tcb)
  (format t "~&~A: ~A" id (tcb-state tcb)))

;;; Utilities

;; Interfaces

(defun ifconfig-address (iface ip &optional (netmask 24))
  (let* ((netmask-ip (as-netmask netmask))
         (network-ip (mask-ip ip netmask-ip))
         (broadcast-ip (broadcast-ip network-ip netmask-ip)))
    (setf (interface-ip iface) ip
          (interface-netmask iface) netmask-ip
          (interface-network-ip iface) network-ip
          (interface-broadcast-ip iface) broadcast-ip)
    (add-route (make-net-route network-ip netmask-ip iface)))
  iface)

(defun netstat (&optional interface)
  (multiple-value-prog1 (values)
    (etypecase interface
      (null
       (mapc #'netstat-interface *interfaces*))
      (interface
       (netstat-interface interface))
      (string
       (let ((iface (find-interface interface)))
         (if iface
             (netstat-interface iface)
             (error "Not a valid interface name: ~S" interface)))))))

(defun netstat-interface (iface &optional (stream *standard-output*))
  (format stream
          "~&~<~@6<~A~> ~<~I~@4<~A~>  Type:~A  HWaddr ~A~_Inet addr:~A/~A  Bcast:~A~_RX bytes:~A (~A)  TX bytes:~A (~A)>~:>~:>~2%"
          (list (interface-name iface)
                (list (if (interface-up? iface) "UP" "DOWN")
                      (interface-type iface)
                      (mac-addr-to-string (interface-mac iface) t)
                      (ip-addr-to-string (interface-ip iface) t)
                      (ip-addr-to-string (interface-netmask iface) t)
                      (ip-addr-to-string (interface-broadcast-ip iface) t)
                      (interface-bytes-in iface)
                      (format-byte-size (interface-bytes-in iface))
                      (interface-bytes-out iface)
                      (format-byte-size (interface-bytes-out iface))))))

(defun format-byte-size (n &optional (stream nil))
  (cond ((>= n 1000000000) (format stream "~,1FGiB" (/ n 1000000000)))
        ((>= n 1000000)    (format stream "~,1FMiB" (/ n 1000000)))
        ((>= n 1000)       (format stream "~,1FKiB" (/ n 1000)))
        (t                 (format stream "~A b" n))))

;; Routes

(defun routes (&optional (stream t))
  "Print a summary of the routing table."
  (print-route-summary stream "Destination" "Gateway" "Netmask" "Interface")
  (mapc #'print-route *routes*)
  (values))

(defun print-route (route &optional (stream *standard-output*))
  (print-route-summary stream
                       (ip-addr-to-string (route-destination route) t)
                       (ip-addr-to-string (route-gateway route) t)
                       (ip-addr-to-string (route-netmask route) t)
                       (interface-name (route-interface route))))

(defun print-route-summary (stream dest gateway netmask interface)
  (format stream "~%~@16<~A~> ~@16<~A~> ~@16<~A~> ~A"
          dest gateway netmask interface))


;; Extras...

(defun udpflood (iface dest high-byte power)
  (let* ((ethh (make-ethh :dest #e"00:C0:95:E4:30:2F"
                          :src  #e"00:08:74:E4:6E:BC"
                          :type ethtype-ip))
         (iph (make-iph :version 4
                        :hlen 5
                        :tos 0
                        :id 0
                        :flags 0
                        :fragment-offset 0
                        :ttl 64
                        :protocol ip-protocol-udp
                        :checksum 0
                        :source 1
                        :dest dest
                        :options '()))
         (udph (make-udph :src-port 9111
                          :dest-port 9111
                          :length 3
                          :checksum 0
                          :data "foo"))
         (packet (list ethh iph udph)))
    (dotimes (i (expt 10 power))
      (let ((sip (netlib::make-ip-addr :value
                                       (netlib::int-to-octet-array
                                        (dpb high-byte
                                             (byte 8 24)
                                             (random (expt 2 24)))
                                        4))))
        (setf (iph-source iph) sip)
        (transmit (interface-dev iface) (packet-to-frame packet))))))

