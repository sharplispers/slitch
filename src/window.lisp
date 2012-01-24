;;; window.lisp -- sliding window data structure for TCP buffers

(defpackage :window
  (:use :common-lisp)
  (:export :make-window :window-p
           :window-start :window-end :window-length :window-filled-pos
           :window-write :window-read :window-advance
           :window-full-p))

(in-package :window)

;; ------------------------------------------------------------
;; Windows
;;
;; +--------------------------------------------------+
;; |************************        **************    |
;; +--------------------------------------------------+
;;  <- region 1 ----------->        <- region 2 ->
;;  ^                      ^                          ^
;;  start-pos              filled-pos                 end-pos

(defstruct (window (:constructor %make-window
				 (start length buffer)))
  "Sliding window data structure.
  BUFFER is a string containing the data in the window.
  LENGTH is the total size of the window.
  REGIONS is an ordered non-overlapping list of (START . END)."
  (start   nil :type integer)
  (length  nil :type integer)
  (origin  0   :type integer)
  (buffer  nil :type string)
  (regions '() :type list))

(defstruct (region (:constructor make-region (start end)))
  (start nil :type integer)
  (end   nil :type integer))

;; Window operations:
;; 

(defun make-window (length &optional (start 0))
  "Make a sliding window LENGTH bytes long, beginning at position START."
  (%make-window start length (make-string length)))

(defun window-filled-pos (window)
  "Return the 'filled position' of WINDOW - the rightmost position
  with no empty space on its left."
  (if (and (window-regions window)
           (= (region-start (car (window-regions window)))
              (window-start window)))
      (region-end (car (window-regions window)))
      (window-start window)))

(defun window-write (window window-pos data)
  "Write DATA into WINDOW starting at WINDOW-POS."
  ;; Writing is divided into two "chunks", one directly after the
  ;; insertion point, and one (possibly empty) wrapped back to the
  ;; beginning.
  (let* ((len (length data))
	 ;; size and position of 
	 (chunk1-pos (+ (window-origin window)
			(- window-pos (window-start window))))
	 (chunk1-size (min len
			   (- (window-length window) chunk1-pos)))
	 (chunk2-size (min (- len chunk1-size)
			   (window-origin window)))
	 (buf (window-buffer window)))
    ;; copy from the insertion point
    (array-copy chunk1-size data 0 buf chunk1-pos)
    ;; copy the wrapped-around area (maybe empty)
    (array-copy chunk2-size data chunk1-size buf 0)
    ;; Update regions
    (let* ((start window-pos)
           (end   (min (+ start len)
                       (window-end window))))
      (setf (window-regions window)
            (add-window-region start end (window-regions window))))))

(defun add-window-region (start end regions)
  "Update the set of REGIONS to include START and END."
  (cond ((= start end)
         ;; range is empty
         regions)
        ((null regions)
         (list (make-region start end)))
        ((> start (region-end (car regions)))
         ;; range is after this region
         (cons (car regions)
               (add-window-region start end (cdr regions))))
        ((< end (region-start (car regions)))
         ;; range is before this region
         (cons (make-region start end) regions))
        (t
         ;; range overlaps with this region - merge
         (add-window-region (min start (region-start (car regions)))
                            (max end   (region-end   (car regions)))
                            (cdr regions)))))

(defun window-end (window)
  "Return the righthand edge of WINDOW."
  (+ (window-start window) (window-length window)))

(defun window-full-p (window)
  (let ((last (car (last (window-regions window)))))
    (and last 
         (= (region-end last) (window-end window)))))

(defun window-read (window bytes)
  (subseq (window-buffer window) 0 bytes))

(defun window-advance (window bytes)
  (incf (window-start window) bytes)
  (do ()
      ((or (null (window-regions window))
           (>= (region-start (car (window-regions window)))
               (window-start window))))
    (let ((r (car (window-regions window))))
      (if (<= (region-end r) (window-start window))
          (pop (window-regions window))
          (setf (region-start r) (window-start window))))))

(defun array-copy (len src-array src-start dst-array dst-start)
  "Copy the LEN elemets from SRC-ARRAY (from SRC-START) into DST-ARRAY
  (from DST-START.)"
  (do ((copied  0         (1+ copied))
       (src-pos src-start (1+ src-pos))
       (dst-pos dst-start (1+ dst-pos)))
      ((= copied len) t)
    (setf (aref dst-array dst-pos)
	  (aref src-array src-pos))))


