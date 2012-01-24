(in-package :binary-types)

(export '(binary-writer-fn defun-binary-writer
          binary-reader-fn defun-binary-reader))

;; ----------------------------------------
;; Output.

(defmacro binary-writer-fn (binary-type)
  `(lambda (object buffer-spec)
    (let ((buffer (make-buffer buffer-spec)))
      ,(generate-writer (find-binary-type binary-type)))))

(defmacro defun-binary-writer (function-name binary-type &optional doc)
  `(defun ,function-name (object &optional
                          (buffer-spec 512))
    (let ((buffer (make-buffer buffer-spec)))
      ,@(if doc (list doc) ())
      ,(generate-writer (find-binary-type binary-type)))))

(defun make-buffer (spec)
  (etypecase spec
    (simple-array spec)
    (integer      (make-array (list spec) :element-type '(unsigned-byte 8)))))

(defun generate-writer (type)
  "Generate code for writing the type described by SPEC.
Assumes the environment includes:
  OBJECT -- the object to write;
  BUFFER -- vector with a fill-pointer to write output into."
  `(let ((bit-buffer    0)
         (bits-buffered 0)
         (bytes-written 0))
    (declare (type (simple-array (unsigned-byte 8) (*)) buffer)
             (type ,(binary-type-name type)         object)
             (type (unsigned-byte 8)                bit-buffer)
             (type fixnum                           bits-buffered)
             (type fixnum                           bytes-written))
    (labels ((output-byte! (value)
               (setf (aref buffer bytes-written) value)
               (incf bytes-written))
             (output-bits! (value bits)
               "Output BITS of VALUE (buffered into whole bytes.)"
               (declare (type fixnum value bits))
               (loop
                (let ((take-bits (min bits (- 8 bits-buffered))))
                  (setf bit-buffer
                        (dpb (ldb (byte take-bits (- bits take-bits)) value)
                             (byte take-bits (- 8 (+ take-bits bits-buffered)))
                             bit-buffer))
                  (incf bits-buffered take-bits)
                  (decf bits take-bits)
                  (when (= 8 bits-buffered)
                    (output-byte! bit-buffer)
                    (setf bits-buffered 0))
                  (when (zerop bits) (return t))))))
      ,(generate-type-writer type 'object)
      (adjust-array buffer (list bytes-written)))))

(defgeneric generate-type-writer (type object-form))

(defmethod generate-type-writer ((type binary-integer) object-form)
  (let ((bits (* 8 (sizeof type))))
    (if (typep type 'binary-bitflag)
        `(output-bits! (if ,object-form 1 0) ,bits)
        `(output-bits! ,object-form ,bits))))

(defmethod generate-type-writer ((type binary-vector) object-form)
  `(let ((object ,object-form))
    (dotimes (i ,(binary-vector-size type))
      ,(generate-type-writer
        (find-binary-type (binary-vector-element-type type))
        '(aref object i)))))

(defmethod generate-type-writer ((type binary-record) object-form)
  `(let ((object ,object-form))
    ,@(loop for slot in (binary-record-slots type)
            collect
            (let ((slot-name (car slot))
                  (slot-type (find-binary-type (cadr slot))))
              (generate-type-writer slot-type `(slot-value object ',slot-name))))))

;; ----------------------------------------
;; Input.

(defmacro binary-reader-fn (binary-type)
  `(lambda (stream)
    ,(generate-reader (find-binary-type binary-type))))

(defmacro defun-binary-reader (function-name binary-type &optional doc)
  `(defun ,function-name (vector)
    (with-binary-input-from-vector (stream vector)
    ,@(if doc (list doc) ())
      ,(generate-reader (find-binary-type binary-type)))))

(defun generate-reader (type)
  `(let ((bit-buffer 0)
         (bits-buffered 0))
    (declare (type (unsigned-byte 8) bit-buffer)
             (type (integer 0 8) bits-buffered))
    (labels ((input-byte! ()
               (aref (cdr stream) (incf (car stream))))
             (input-bits! (bits)
               (let ((value 0))
                 (loop
                  (when (zerop bits-buffered)
                    (setf bit-buffer (input-byte!))
                    (setf bits-buffered 8))
                  (let ((take-bits (min bits-buffered bits)))
                    (setf value (dpb (ldb (byte take-bits
                                                (- bits-buffered take-bits))
                                          bit-buffer)
                                     (byte take-bits (- bits take-bits))
                                     value))
                    (decf bits-buffered take-bits)
                    (when (zerop (decf bits take-bits))
                      (return value)))))))
      ,(generate-type-reader type))))

(defgeneric generate-type-reader (type))

(defmethod generate-type-reader ((type binary-integer))
  (if (typep type 'binary-bitflag)
      '(= 1 (input-bits! 1))
      `(input-bits! ,(* 8 (sizeof type)))))

(defmethod generate-type-reader ((type binary-vector))
  (let* ((size (binary-vector-size type))
         (elem-type-name (binary-vector-element-type type))
         (elem-type (find-binary-type elem-type-name)))
  `(let ((vector (make-array '(,size) :element-type ',elem-type-name)))
    (dotimes (i ,size)
      (setf (aref vector i) ,(generate-type-reader elem-type)))
    vector)))

(defmethod generate-type-reader ((type binary-record))
  `(let* ((type (find-binary-type ',(binary-type-name type)))
          (object (binary-record-make-instance type)))
    ,@(loop for slot in (binary-record-slots type)
            collect
            (let ((slot-name (car slot))
                  (slot-type (find-binary-type (cadr slot))))
              `(setf (slot-value object ',slot-name)
                     ,(generate-type-reader slot-type))))
    object))

