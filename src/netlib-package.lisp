(defpackage :netlib
  (:use :common-lisp :unix :alien :c-call :tuntap :binary-types)
  (:export

   :packet-to-frame :with-input-from-frame

   :device
   :transmit :enable-device :disable-device :destroy-device
   :make-tap-device :make-packet-socket-device

   :read-vector

   :ip-addr

   :mac-addr :ethernet-multicast-p
   :broadcast-mac  :mac-addr-to-string :random-mac-addr

   :ethh :make-ethh :read-ethh
   :ethh-dest :ethh-src :ethh-type
   :ethtype-arp :ethtype-rarp :ethtype-ip

   :arph :make-arph :read-arph
   :arph-hardware-type :arph-protocol-type :arph-hardware-length
   :arph-protocol-length :arph-operation :arph-sender-ha
   :arph-sender-ip :arph-target-ha :arph-target-ip
   :arp-operation-request :arp-operation-response

   :iph :make-iph :read-iph
   :iph-version :iph-hlen :iph-tos :iph-total-len :iph-id
   :iph-flags :iph-fragment-offset :iph-ttl :iph-protocol :iph-checksum
   :iph-source :iph-dest :iph-options
   :ip-protocol-icmp :ip-protocol-tcp :ip-protocol-udp
   :ipopt-end-of-options :ipopt-nop :ipopt-security
   :ipopt-loose-source-routing :ipopt-strict-source-routing
   :ipopt-record-route :ipopt-stream-id :ipopt-timestamp
   :ip-addr-to-string

   :icmph :make-icmph :read-icmph
   :icmph-type :icmph-code :icmph-checksum :icmph-data
   :icmp-type-echo-request :icmp-type-echo-reply :icmp-type-port-unreachable

   :udph :make-udph :read-udph
   :udph-src-ip :udph-dest-ip :udph-src-port :udph-dest-port
   :udph-length :udph-checksum :udph-data

   :tcph :make-tcph :read-tcph
   :tcph-src-ip :tcph-dest-ip :tcph-src-port :tcph-dest-port
   :tcph-seq :tcph-ack-seq :tcph-data-offset :tcph-reserved
   :tcph-urg? :tcph-ack? :tcph-psh? :tcph-rst? :tcph-syn? :tcph-fin?
   :tcph-window :tcph-checksum :tcph-urgent-ptr :tcph-options
   :tcph-data

   :as-netmask :prefix-bits-to-netmask :netmask-to-prefix-bits :mask-ip
   :broadcast-ip :ip>= :ip<
   ))
