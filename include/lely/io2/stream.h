/**@file
 * This header file is part of the I/O library; it contains the abstract I/O
 * stream interface.
 *
 * @copyright 2019 Lely Industries N.V.
 *
 * @author J. S. Seldenthuis <jseldenthuis@lely.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LELY_IO2_STREAM_H_
#define LELY_IO2_STREAM_H_

#include <lely/ev/future.h>
#include <lely/ev/task.h>
#include <lely/io2/buf.h>
#include <lely/io2/dev.h>
#if _WIN32
#include <lely/io2/win32/poll.h>
#endif
#include <lely/libc/sys/types.h>

#ifndef LELY_IO_STREAM_INLINE
#define LELY_IO_STREAM_INLINE static inline
#endif

/// An abstract I/O stream.
typedef const struct io_stream_vtbl *const io_stream_t;

/// The result of read or write operation on an I/O stream.
struct io_stream_result {
	/**
	 * The number of bytes read or written, 0 on end-of-file, or -1 on error
	 * (or if the operation is canceled). In the latter case, the error
	 * number is stored in #errc.
	 */
	ssize_t result;
	/// The error number, obtained as if by get_errc(), if #result is -1.
	int errc;
};

/**
 * A vectored I/O stream read operation. The operation is performed as if by
 * POSIX `readv()`.
 */
struct io_stream_readv {
	/**
	 * A pointer to an array of mutable buffers. Input data from a read
	 * operation is scattered into the buffers in order. The read operation
	 * SHALL always fill a buffer completely before proceeding to the next.
	 * It is the responsibility of the user to ensure the array of buffers
	 * remains valid until the operation completes.
	 */
	const struct io_buf *buf;
	/**
	 * The number of entries in #buf. This number MUST be positive and MAY
	 * have an implementation-defined upper limit.
	 */
	int bufcnt;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_stream_result r;
#if _WIN32
	// The handle passed to `GetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_stream_readv.
#if _WIN32
#define IO_STREAM_READV_INIT(buf, bufcnt, exec, func) \
	{ \
		(buf), (bufcnt), EV_TASK_INIT(exec, func), { 0, 0 }, NULL, \
				IO_CP_INIT(NULL) \
	}
#else
#define IO_STREAM_READV_INIT(buf, bufcnt, exec, func) \
	{ \
		(buf), (bufcnt), EV_TASK_INIT(exec, func), { 0, 0 }, \
	}
#endif

/**
 * An I/O stream read operation. The operation is performed as if by POSIX
 * `read()`.
 */
struct io_stream_read {
	/// The vectored read operation.
	struct io_stream_readv readv;
	/// The read buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_stream_read. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_STREAM_READ_INIT(self, base, len, exec, func) \
	{ \
		IO_STREAM_READV_INIT((self)->buf, 1, (exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

/**
 * A vectored I/O stream write operation. The operation is performed as if by
 * POSIX `writev()`.
 */
struct io_stream_writev {
	/**
	 * A pointer to an array of constant buffers. Output data for a write
	 * operation is gathered from the buffers in order. The write operation
	 * SHALL always write a complete buffer buffer before proceeding to the
	 * next. It is the responsibility of the user to ensure the array of
	 * buffers remains valid until the operation completes.
	 */
	const struct io_buf *buf;
	/**
	 * The number of entries in #buf. This number MUST be positive and MAY
	 * have an implementation-defined upper limit.
	 */
	int bufcnt;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_stream_result r;
#if _WIN32
	// The handle passed to `GetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_stream_writev.
#if _WIN32
#define IO_STREAM_WRITEV_INIT(buf, bufcnt, exec, func) \
	{ \
		(buf), (bufcnt), EV_TASK_INIT(exec, func), { 0, 0 }, NULL, \
				IO_CP_INIT(NULL) \
	}
#else
#define IO_STREAM_WRITEV_INIT(buf, bufcnt, exec, func) \
	{ \
		(buf), (bufcnt), EV_TASK_INIT(exec, func), { 0, 0 } \
	}
#endif

/**
 * An I/O stream write operation. The operation is performed as if by POSIX
 * `write()`.
 */
struct io_stream_write {
	/// The vectored write operation.
	struct io_stream_writev writev;
	/// The write buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_stream_write. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_STREAM_WRITE_INIT(self, base, len, exec, func) \
	{ \
		IO_STREAM_WRITEV_INIT((self)->buf, 1, (exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

#ifdef __cplusplus
extern "C" {
#endif

struct io_stream_vtbl {
	io_dev_t *(*get_dev)(const io_stream_t *stream);
	ssize_t (*readv)(io_stream_t *stream, const struct io_buf *buf,
			int bufcnt);
	void (*submit_readv)(
			io_stream_t *stream, struct io_stream_readv *readv);
	ssize_t (*writev)(io_stream_t *stream, const struct io_buf *buf,
			int bufcnt);
	void (*submit_writev)(
			io_stream_t *stream, struct io_stream_writev *writev);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_stream_get_ctx(const io_stream_t *stream);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_stream_get_exec(const io_stream_t *stream);

/// @see io_dev_cancel()
static inline size_t io_stream_cancel(
		io_stream_t *stream, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_stream_abort(io_stream_t *stream, struct ev_task *task);

/// Returns a pointer to the abstract I/O device representing the I/O stream.
LELY_IO_STREAM_INLINE io_dev_t *io_stream_get_dev(const io_stream_t *stream);

/**
 * Equivalent to io_stream_read(), except that the input data is scattered into
 * the <b>bufcnt</b> buffers specified by the members of the <b>buf</b> array.
 * The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_STREAM_INLINE ssize_t io_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);

/**
 * Submits a vectored read operation to an I/O stream. The completion task is
 * submitted for execution once one or more bytes have been read or a read error
 * occurs.
 */
LELY_IO_STREAM_INLINE void io_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv);

/**
 * Cancels the specified vectored I/O stream read operation if it is pending.
 * The completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_stream_cancel_readv(
		io_stream_t *stream, struct io_stream_readv *readv);

/**
 * Aborts the specified vectored I/O stream read operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_stream_abort_readv(
		io_stream_t *stream, struct io_stream_readv *readv);

/**
 * Equivalent to io_stream_async_read(), except that the input data is scattered
 * into the <b>bufcnt</b> buffers specified by the members of the <b>buf</b>
 * array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_stream_async_readv(io_stream_t *stream, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv);

/**
 * Attempts to read <b>nbytes</b> bytes from an I/O stream as if by POSIX
 * `read()`. This function blocks until at least one byte is read, the
 * end-of-file is reached or an error occurs.
 *
 * @param stream a pointer to an I/O stream.
 * @param buf    the address at which to store the bytes.
 * @param nbytes the number of bytes to read.
 *
 * @returns the number of bytes read on success, 0 on end-of-file, or -1 on
 * error. In the latter case, the error number can be obtained with get_errc().
 */
LELY_IO_STREAM_INLINE ssize_t io_stream_read(
		io_stream_t *stream, void *buf, size_t nbytes);

/**
 * Submits a read operation to an I/O stream. The completion task is submitted
 * for execution once one or more bytes have been read or a read error occurs.
 */
LELY_IO_STREAM_INLINE void io_stream_submit_read(
		io_stream_t *stream, struct io_stream_read *read);

/**
 * Cancels the specified I/O stream read operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_stream_cancel_read(
		io_stream_t *stream, struct io_stream_read *read);

/**
 * Aborts the specified I/O stream read operation if it is pending. If aborted,
 * the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_stream_abort_read(
		io_stream_t *stream, struct io_stream_read *read);

/**
 * Submits an asynchronous read operation to an I/O stream and creates a future
 * which becomes ready once the read operation completes (or is canceled). The
 * result of the future has type #io_stream_result.
 *
 * @param stream a pointer to an I/O stream.
 * @param exec   a pointer to the executor used to execute the completion
 *               function of the read operation. If NULL, the default executor
 *               of the I/O stream is used.
 * @param buf    the address at which to store the bytes.
 * @param nbytes the number of bytes to read.
 * @param pread  the address at which to store a pointer to the read operation
 *               (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_stream_async_read(io_stream_t *stream, ev_exec_t *exec,
		void *buf, size_t nbytes, struct io_stream_read **pread);

/**
 * Equivalent to io_stream_write(), except that the output data is gathered from
 * the <b>bufcnt</b> buffers specified by the members of the <b>buf</b> array.
 * The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_STREAM_INLINE ssize_t io_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);

/**
 * Submits a vectored write operation to an I/O stream. The completion task is
 * submitted for execution once the bytes have been written or a write error
 * occurs.
 */
LELY_IO_STREAM_INLINE void io_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

/**
 * Cancels the specified vectored I/O stream write operation if it is pending.
 * The completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_stream_cancel_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

/**
 * Aborts the specified vectored I/O stream write operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_stream_abort_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

/**
 * Equivalent to io_stream_async_write(), except that the output data is
 * gathered from the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_stream_async_writev(io_stream_t *stream, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev);

/**
 * Attempts to write <b>nbytes</b> bytes to an I/O stream as if by POSIX
 * `write()`. This function blocks until the bytes are written or an error
 * occurs.
 *
 * @param stream a pointer to an I/O stream.
 * @param buf    a pointer to the bytes to be written.
 * @param nbytes the number of bytes to write.
 *
 * @returns the number of bytes written, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
LELY_IO_STREAM_INLINE ssize_t io_stream_write(
		io_stream_t *stream, const void *buf, size_t nbytes);

/**
 * Submits a write operation to an I/O stream. The completion task is submitted
 * for execution once the bytes have been written or a write error occurs.
 */
LELY_IO_STREAM_INLINE void io_stream_submit_write(
		io_stream_t *stream, struct io_stream_write *write);

/**
 * Cancels the specified I/O stream write operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_stream_cancel_write(
		io_stream_t *stream, struct io_stream_write *write);

/**
 * Aborts the specified I/O stream write operation if it is pending. If aborted,
 * the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_stream_abort_write(
		io_stream_t *stream, struct io_stream_write *write);

/**
 * Submits an asynchronous write operation to an I/O stream and creates a future
 * which becomes ready once the write operation completes (or is canceled). The
 * result of the future has type #io_stream_result.
 *
 * @param stream a pointer to an I/O stream.
 * @param exec   a pointer to the executor used to execute the completion
 *               function of the write operation. If NULL, the default executor
 *               of the I/O stream is used.
 * @param buf    a pointer to the bytes to be written.
 * @param nbytes the number of bytes to write.
 * @param pwrite the address at which to store a pointer to the write operation
 *               (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_stream_async_write(io_stream_t *stream, ev_exec_t *exec,
		const void *buf, size_t nbytes,
		struct io_stream_write **pwrite);

/**
 * Obtains a pointer to a vectored I/O stream read operation from a pointer to
 * its completion task.
 */
struct io_stream_readv *io_stream_readv_from_task(struct ev_task *task);

/**
 * Obtains a pointer to an I/O stream read operation from a pointer to its
 * completion task.
 */
struct io_stream_read *io_stream_read_from_task(struct ev_task *task);

/**
 * Obtains a pointer to a vectored I/O stream write operation from a pointer to
 * its completion task.
 */
struct io_stream_writev *io_stream_writev_from_task(struct ev_task *task);

/**
 * Obtains a pointer to an I/O stream write operation from a pointer to its
 * completion task.
 */
struct io_stream_write *io_stream_write_from_task(struct ev_task *task);

static inline io_ctx_t *
io_stream_get_ctx(const io_stream_t *stream)
{
	return io_dev_get_ctx(io_stream_get_dev(stream));
}

static inline ev_exec_t *
io_stream_get_exec(const io_stream_t *stream)
{
	return io_dev_get_exec(io_stream_get_dev(stream));
}

static inline size_t
io_stream_cancel(io_stream_t *stream, struct ev_task *task)
{
	return io_dev_cancel(io_stream_get_dev(stream), task);
}

static inline size_t
io_stream_abort(io_stream_t *stream, struct ev_task *task)
{
	return io_dev_abort(io_stream_get_dev(stream), task);
}

inline io_dev_t *
io_stream_get_dev(const io_stream_t *stream)
{
	return (*stream)->get_dev(stream);
}

inline ssize_t
io_stream_readv(io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	return (*stream)->readv(stream, buf, bufcnt);
}

inline void
io_stream_submit_readv(io_stream_t *stream, struct io_stream_readv *readv)
{
	(*stream)->submit_readv(stream, readv);
}

static inline size_t
io_stream_cancel_readv(io_stream_t *stream, struct io_stream_readv *readv)
{
	return io_stream_cancel(stream, &readv->task);
}

static inline size_t
io_stream_abort_readv(io_stream_t *stream, struct io_stream_readv *readv)
{
	return io_stream_abort(stream, &readv->task);
}

inline ssize_t
io_stream_read(io_stream_t *stream, void *buf, size_t nbytes)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_stream_readv(stream, buf_, 1);
}

inline void
io_stream_submit_read(io_stream_t *stream, struct io_stream_read *read)
{
	io_stream_submit_readv(stream, &read->readv);
}

static inline size_t
io_stream_cancel_read(io_stream_t *stream, struct io_stream_read *read)
{
	return io_stream_cancel_readv(stream, &read->readv);
}

static inline size_t
io_stream_abort_read(io_stream_t *stream, struct io_stream_read *read)
{
	return io_stream_abort_readv(stream, &read->readv);
}

inline ssize_t
io_stream_writev(io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	return (*stream)->writev(stream, buf, bufcnt);
}

inline void
io_stream_submit_writev(io_stream_t *stream, struct io_stream_writev *writev)
{
	(*stream)->submit_writev(stream, writev);
}

static inline size_t
io_stream_cancel_writev(io_stream_t *stream, struct io_stream_writev *writev)
{
	return io_stream_cancel(stream, &writev->task);
}

static inline size_t
io_stream_abort_writev(io_stream_t *stream, struct io_stream_writev *writev)
{
	return io_stream_abort(stream, &writev->task);
}

inline ssize_t
io_stream_write(io_stream_t *stream, const void *buf, size_t nbytes)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_stream_writev(stream, buf_, 1);
}

inline void
io_stream_submit_write(io_stream_t *stream, struct io_stream_write *write)
{
	io_stream_submit_writev(stream, &write->writev);
}

static inline size_t
io_stream_cancel_write(io_stream_t *stream, struct io_stream_write *write)
{
	return io_stream_cancel_writev(stream, &write->writev);
}

static inline size_t
io_stream_abort_write(io_stream_t *stream, struct io_stream_write *write)
{
	return io_stream_abort_writev(stream, &write->writev);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_STREAM_H_
