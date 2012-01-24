;;; switch.lisp -- a toy ethernet switch built on `netlib'.
;;; (netlib source is at http://www.sourceforge.net/projects/slitch/)

(defpackage :switch
  (:use :common-lisp)
  (:export :start))

(in-package :switch)

(defvar *devices* nil
  "List of devices to switch between.")

(defvar *fdb* (make-hash-table :test #'equalp)
  "Forwarding database: maps MAC addresses onto network devices.")

(defun start (&rest devices)
  "Start switching packets between DEVICES."
  (setq *devices* devices)
  (mapc #'init-device *devices*))

(defun init-device (device)
  "Initialize DEVICE to pass frames up for switching."
  (netlib:device-enable device
                        ;; This function is called when a frame arrives.
                        ;; FRAME is an ethernet frame as an array of bytes.
                        (lambda (frame) (input frame device))))

(defun input (frame input-device)
  "Process a FRAME arriving on INPUT-DEVICE."
  (multiple-value-bind (source destination) (header-addresses frame)
    (update-fdb source input-device)
    (let ((output-device (where-is destination)))
      (cond ((null output-device)
             (flood frame input-device))
            ((not (eq output-device input-device))
             (send frame output-device))))))

(defun header-addresses (frame)
  "Return the source and destination addresses from FRAME's ethernet header."
  (netlib:with-input-from-frame (stream frame)
    (let ((header (netlib:read-ethh stream)))
      (values (netlib:ethh-src header) (netlib:ethh-dest header)))))

(defun update-fdb (address device)
  "Update the forwarding database: ADDRESS is on DEVICE."
  (unless (netlib:ethernet-multicast-p address)
    (setf (gethash address *fdb*) device)))

(defun where-is (address)
  "Return the device that ADDRESS is on, or NIL if unknown."
  (gethash address *fdb*))

(defun send (frame output-device)
  "Send FRAME to OUTPUT-DEVICE."
  (netlib:transmit output-device frame))

(defun flood (frame input-device)
  "Send FRAME to all devices except INPUT-DEVICE."
  (dolist (output-device *devices*)
    (unless (eq output-device input-device)
      (send frame output-device))))

;;; End of the "screenful" version.

(defun test ()
  "Example: bring up and switch between three tap devices on the host."
  (start (netlib:make-tap-device "switch0")
         (netlib:make-tap-device "switch1")
         (netlib:make-tap-device "switch2")))

(defun stop ()
  "Stop switching and close all the devices."
  (loop for device across *devices*
        do (netlib:netdev-destroy device)))

