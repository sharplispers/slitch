;; Networking constants, derived from RFCs.

(in-package :netlib)

;; Ethernet
(defconstant ethtype-arp  #x0806)
(defconstant ethtype-rarp #x8035)
(defconstant ethtype-ip   #x0800)

(defconstant broadcast-mac #e"FF:FF:FF:FF:FF:FF"
             "The ethernet broadcast address.")

;; ARP
(defconstant arp-operation-request  1)
(defconstant arp-operation-response 2)

;; IPv4
(defconstant ip-protocol-icmp 1)
(defconstant ip-protocol-tcp  6)
(defconstant ip-protocol-udp  17)

;; IP options: control class
(defconstant ipopt-end-of-options        0)
(defconstant ipopt-nop                   1)
(defconstant ipopt-security              2)
(defconstant ipopt-loose-source-routing  3)
(defconstant ipopt-strict-source-routing 9)
(defconstant ipopt-record-route          7)
(defconstant ipopt-stream-id             4)
;; IP options: debugging class
(defconstant ipopt-timestamp 4)

;; ICMP
(defconstant icmp-type-echo-request 8)
(defconstant icmp-type-echo-reply   0)
(defconstant icmp-type-port-unreachable 3)

;; TCP
(defconstant tcpopt-end-of-options 0)
(defconstant tcpopt-nop            1)
(defconstant tcpopt-mss            2)

