/**@file
 * This header file is part of the I/O library; it contains the abstract stream
 * socket interface.
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

#ifndef LELY_IO2_SOCK_STREAM_H_
#define LELY_IO2_SOCK_STREAM_H_

#include <lely/io2/sock.h>
#include <lely/io2/stream.h>

#ifndef LELY_IO_SOCK_STREAM_INLINE
#define LELY_IO_SOCK_STREAM_INLINE static inline
#endif

/// An abstract stream socket.
typedef const struct io_sock_stream_vtbl *const io_sock_stream_t;

/// A stream socket connect operation.
struct io_sock_stream_connect {
	/**
	 * A pointer to the network protocol endpoint of the peer. It is the
	 * responsibility of the user to ensure the endpoint matches the
	 * address family and protocol of the socket
	 */
	const struct io_endp *endp;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/**
	 * The error number, obtained as if by get_errc(), if an error occurred
	 * or the operation was canceled.
	 */
	int errc;
#if _WIN32
	// The socket handle passed to `WSAGetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_stream_connect.
#if _WIN32
#define IO_SOCK_STREAM_CONNECT_INIT(endp, exec, func) \
	{ \
		(endp), EV_TASK_INIT(exec, func), 0, INVALID_HANDLE_VALUE, \
				IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_STREAM_CONNECT_INIT(endp, exec, func) \
	{ \
		(endp), EV_TASK_INIT(exec, func), 0 \
	}
#endif

/**
 * A vectored stream socket receive operation. The operation is performed as if
 * by POSIX `recvmsg()`.
 */
struct io_sock_stream_recvmsg {
	/**
	 * A pointer to an array of mutable buffers. Input data from a receive
	 * operation is scattered into the buffers in order. The receive
	 * operation SHALL always fill a buffer completely before proceeding to
	 * the next. It is the responsibility of the user to ensure the array of
	 * buffers remains valid until the operation completes.
	 */
	const struct io_buf *buf;
	/**
	 * The number of entries in #buf. This number MUST be positive and MAY
	 * have an implementation-defined upper limit.
	 */
	int bufcnt;
	/**
	 * The flags of the receive operation (on input, any combination of
	 * #IO_MSG_OOB and #IO_MSG_PEEK; on output, #IO_MSG_OOB may be set).
	 */
	int flags;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_stream_result r;
#if _WIN32
	// The socket handle passed to `WSAGetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_stream_recvmsg.
#if _WIN32
#define IO_SOCK_STREAM_RECVMSG_INIT(buf, bufcnt, flags, exec, func) \
	{ \
		(buf), (bufcnt), (flags), EV_TASK_INIT(exec, func), { 0, 0 }, \
				INVALID_HANDLE_VALUE, IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_STREAM_RECVMSG_INIT(buf, bufcnt, flags, exec, func) \
	{ \
		(buf), (bufcnt), (flags), EV_TASK_INIT(exec, func), { 0, 0 } \
	}
#endif

/**
 * A stream socket receive operation. The operation is performed as if by POSIX
 * `recv()`.
 */
struct io_sock_stream_recv {
	/// The vectored receive operation.
	struct io_sock_stream_recvmsg recvmsg;
	/// The receive buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_sock_stream_recv. <b>self</b> MUST be the
 * address of the struct being initialized.
 */
#define IO_SOCK_STREAM_RECV_INIT(self, base, len, flags, exec, func) \
	{ \
		IO_SOCK_STREAM_RECVMSG_INIT( \
				(self)->buf, 1, (flags), (exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

/**
 * A vectored stream socket send operation. The operation is performed as if
 * by POSIX `sendmsg()`.
 */
struct io_sock_stream_sendmsg {
	/**
	 * A pointer to an array of constant buffers. Output data for a send
	 * operation is gathered from the buffers in order. The send operation
	 * SHALL always send a complete buffer buffer before proceeding to the
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
	 * The flags of the send operation (any combination of #IO_MSG_DONTROUTE
	 * and #IO_MSG_OOB).
	 */
	int flags;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_stream_result r;
#if _WIN32
	// The socket handle passed to `WSAGetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_stream_sendmsg.
#if _WIN32
#define IO_SOCK_STREAM_SENDMSG_INIT(buf, bufcnt, flags, exec, func) \
	{ \
		(buf), (bufcnt), (flags), EV_TASK_INIT(exec, func), { 0, 0 }, \
				INVALID_HANDLE_VALUE, IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_STREAM_SENDMSG_INIT(buf, bufcnt, flags, exec, func) \
	{ \
		(buf), (bufcnt), (flags), EV_TASK_INIT(exec, func), { 0, 0 } \
	}
#endif

/**
 * A stream socket send operation. The operation is performed as if by POSIX
 * `send()`.
 */
struct io_sock_stream_send {
	/// The vectored send operation.
	struct io_sock_stream_sendmsg sendmsg;
	/// The send buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_sock_stream_send. <b>self</b> MUST be the
 * address of the struct being initialized.
 */
#define IO_SOCK_STREAM_SEND_INIT(self, base, len, flags, exec, func) \
	{ \
		IO_SOCK_STREAM_SENDMSG_INIT( \
				(self)->buf, 1, (flags), (exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

#ifdef __cplusplus
extern "C" {
#endif

struct io_sock_stream_vtbl {
	io_sock_t *(*get_sock)(const io_sock_stream_t *sock);
	io_stream_t *(*get_stream)(const io_sock_stream_t *sock);
	int (*connect)(io_sock_stream_t *sock, const struct io_endp *endp);
	void (*submit_connect)(io_sock_stream_t *sock,
			struct io_sock_stream_connect *connect);
	int (*getpeername)(const io_sock_stream_t *sock, struct io_endp *endp);
	ssize_t (*recvmsg)(io_sock_stream_t *sock, const struct io_buf *buf,
			int bufcnt, int *flags, int timeout);
	void (*submit_recvmsg)(io_sock_stream_t *sock,
			struct io_sock_stream_recvmsg *recvmsg);
	ssize_t (*sendmsg)(io_sock_stream_t *sock, const struct io_buf *buf,
			int bufcnt, int flags, int timeout);
	void (*submit_sendmsg)(io_sock_stream_t *sock,
			struct io_sock_stream_sendmsg *sendmsg);
	int (*shutdown)(io_sock_stream_t *sock, int type);
	int (*get_keepalive)(const io_sock_stream_t *sock);
	int (*set_keepalive)(io_sock_stream_t *sock, int optval);
	int (*get_linger)(const io_sock_stream_t *sock, int *ponoff,
			int *plinger);
	int (*set_linger)(io_sock_stream_t *sock, int onoff, int linger);
	int (*get_oobinline)(const io_sock_stream_t *sock);
	int (*set_oobinline)(io_sock_stream_t *sock, int optval);
	int (*atmark)(const io_sock_stream_t *sock);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_sock_stream_get_ctx(const io_sock_stream_t *sock);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_sock_stream_get_exec(const io_sock_stream_t *sock);

/// @see io_dev_cancel()
static inline size_t io_sock_stream_cancel(
		io_sock_stream_t *sock, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_sock_stream_abort(
		io_sock_stream_t *sock, struct ev_task *task);

/// @see io_sock_get_dev()
static inline io_dev_t *io_sock_stream_get_dev(const io_sock_stream_t *sock);

/// @see io_sock_bind()
static inline int io_sock_stream_bind(io_sock_stream_t *sock,
		const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_sock_stream_getsockname(
		const io_sock_stream_t *sock, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_sock_stream_is_open(const io_sock_stream_t *sock);

/// @see io_sock_close()
static inline int io_sock_stream_close(io_sock_stream_t *sock);

/// @see io_sock_wait()
static inline int io_sock_stream_wait(
		io_sock_stream_t *sock, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_sock_stream_submit_wait(
		io_sock_stream_t *sock, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_sock_stream_cancel_wait(
		io_sock_stream_t *sock, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_sock_stream_abort_wait(
		io_sock_stream_t *sock, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_sock_stream_async_wait(io_sock_stream_t *sock,
		ev_exec_t *exec, int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_sock_stream_get_error(io_sock_stream_t *sock);

/// @see io_sock_get_nread()
static inline int io_sock_stream_get_nread(const io_sock_stream_t *sock);

/// @see io_sock_get_dontroute()
static inline int io_sock_stream_get_dontroute(const io_sock_stream_t *sock);

/// @see io_sock_set_dontroute()
static inline int io_sock_stream_set_dontroute(
		io_sock_stream_t *sock, int optval);

/// @see io_sock_get_rcvbuf()
static inline int io_sock_stream_get_rcvbuf(const io_sock_stream_t *sock);

/// @see io_sock_set_rcvbuf()
static inline int io_sock_stream_set_rcvbuf(io_sock_stream_t *sock, int optval);

/// @see io_sock_get_sndbuf()
static inline int io_sock_stream_get_sndbuf(const io_sock_stream_t *sock);

/// @see io_sock_set_sndbuf()
static inline int io_sock_stream_set_sndbuf(io_sock_stream_t *sock, int optval);

/// @see io_stream_readv()
static inline ssize_t io_sock_stream_readv(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_readv()
static inline void io_sock_stream_submit_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv);

/// @see io_stream_cancel_readv()
static inline size_t io_sock_stream_cancel_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv);

/// @see io_stream_abort_readv()
static inline size_t io_sock_stream_abort_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv);

/// @see io_stream_async_readv()
static inline ev_future_t *io_sock_stream_async_readv(io_sock_stream_t *sock,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv);

/// @see io_stream_read()
static inline ssize_t io_sock_stream_read(
		io_sock_stream_t *sock, void *buf, size_t nbytes);

/// @see io_stream_submit_read()
static inline void io_sock_stream_submit_read(
		io_sock_stream_t *sock, struct io_stream_read *read);

/// @see io_stream_cancel_read()
static inline size_t io_sock_stream_cancel_read(
		io_sock_stream_t *sock, struct io_stream_read *read);

/// @see io_stream_abort_read()
static inline size_t io_sock_stream_abort_read(
		io_sock_stream_t *sock, struct io_stream_read *read);

/// @see io_stream_async_read()
static inline ev_future_t *io_sock_stream_async_read(io_sock_stream_t *sock,
		ev_exec_t *exec, void *buf, size_t nbytes,
		struct io_stream_read **pread);

/// @see io_stream_writev()
static inline ssize_t io_sock_stream_writev(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_writev()
static inline void io_sock_stream_submit_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev);

/// @see io_stream_cancel_writev()
static inline size_t io_sock_stream_cancel_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev);

/// @see io_stream_abort_writev()
static inline size_t io_sock_stream_abort_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev);

/// @see io_stream_async_writev()
static inline ev_future_t *io_sock_stream_async_writev(io_sock_stream_t *sock,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev);

/// @see io_stream_write()
static inline ssize_t io_sock_stream_write(
		io_sock_stream_t *sock, const void *buf, size_t nbytes);

/// @see io_stream_submit_write()
static inline void io_sock_stream_submit_write(
		io_sock_stream_t *sock, struct io_stream_write *write);

/// @see io_stream_cancel_write()
static inline size_t io_sock_stream_cancel_write(
		io_sock_stream_t *sock, struct io_stream_write *write);

/// @see io_stream_abort_write()
static inline size_t io_sock_stream_abort_write(
		io_sock_stream_t *sock, struct io_stream_write *write);

/// @see io_stream_async_write()
static inline ev_future_t *io_sock_stream_async_write(io_sock_stream_t *sock,
		ev_exec_t *exec, const void *buf, size_t nbytes,
		struct io_stream_write **pwrite);

/// Returns a pointer to the abstract socket representing the stream socket.
LELY_IO_SOCK_STREAM_INLINE io_sock_t *io_sock_stream_get_sock(
		const io_sock_stream_t *sock);

/// Returns a pointer to the abstract stream representing the stream socket.
LELY_IO_SOCK_STREAM_INLINE io_stream_t *io_sock_stream_get_stream(
		const io_sock_stream_t *sock);

/**
 * Attempts to connect an open, but unconnected, stream socket to the specified
 * peer endpoint as if by POSIX `connect()`. If the socket has not already been
 * bound to a local endpoint, this function SHALL bind it to an unused endpoint.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * cann be obtained with get_errc().
 *
 * @see io_sock_stream_getpeername()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_connect(
		io_sock_stream_t *sock, const struct io_endp *endp);

/**
 * Submits a connect operation to a stream socket. The completion task is
 * submitted for execution once a connection has been established or an error
 * occurs.
 */
LELY_IO_SOCK_STREAM_INLINE void io_sock_stream_submit_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect);

/**
 * Cancels the specified stream socket connect operation if it is pending. The
 * completion task is submitted for execution with
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_cancel_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect);

/**
 * Aborts the specified stream socket connect operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_abort_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect);

/**
 * Submits an asynchronous connect operation to a stream socket and creates a
 * future which becomes ready once the connect operation completes (or is
 * canceled).  The result of the future is an `int` containing the error number.
 *
 * @param sock     a pointer to an open, but unconnected, stream socket.
 * @param exec     a pointer to the executor used to execute the completion
 *                 function of the connect operation. If NULL, the default
 *                 executor of the stream socket is used.
 * @param endp     a pointer to the network protocol endpoint of the peer. It is
 *                 the responsibility of the user to ensure the endpoint matches
 *                 the address family and protocol of the socket
 * @param pconnect the address at which to store a pointer to the connect
 *                 operation (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_stream_async_connect(io_sock_stream_t *sock,
		ev_exec_t *exec, const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect);

/**
 * Obtains the network protocol endpoint of the peer connected to a stream
 * socket as if by POSIX `getpeername()`.
 *
 * @param sock a pointer to a stream socket.
 * @param endp the address at which to store the endpoint. If not NULL, it is
 *             the responsibility of the user to ensure the endpoint matches the
 *             address family and protocol of the socket.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_stream_connect()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_getpeername(
		const io_sock_stream_t *sock, struct io_endp *endp);

/**
 * Equivalent to io_sock_stream_recv(), except that the input data is scattered
 * into the <b>bufcnt</b> buffers specified by the members of the <b>buf</b>
 * array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_SOCK_STREAM_INLINE ssize_t io_sock_stream_recvmsg(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt,
		int *flags, int timeout);

/**
 * Submits a vectored receive operation to a stream socket. The completion task
 * is submitted for execution once one or more bytes have been received or an
 * error occurs.
 */
LELY_IO_SOCK_STREAM_INLINE void io_sock_stream_submit_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg);

/**
 * Cancels the specified vectored stream socket receive operation if it is
 * pending. The completion task is submitted for execution with
 * <b>result</b> = -1 and <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_cancel_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg);

/**
 * Aborts the specified vectored stream socket receive operation if it is
 * pending. If aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_abort_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg);

/**
 * Equivalent to io_sock_stream_async_recv(), except that the input data is
 * scattered into the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_sock_stream_async_recvmsg(io_sock_stream_t *sock,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		int *flags, struct io_sock_stream_recvmsg **precvmsg);

/**
 * Receives a message from a stream socket as if by POSIX `recv()`. With
 * *<b>flags</b> = 0, this function is equivalent to io_stream_read().
 *
 * @param sock    a pointer to a stream socket.
 * @param buf     the address at which to store the bytes.
 * @param nbytes  the number of bytes to receive.
 * @param flags   a pointer to the flags of the receive operation (on input, any
 *                combination of #IO_MSG_OOB and #IO_MSG_PEEK; on output,
 *                #IO_MSG_OOB may be set).
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns the number of bytes received on success, 0 when the peer has
 * performed an orderly shutdown, or -1 on error. In the latter case, the error
 * number can be obtained with get_errc().
 */
LELY_IO_SOCK_STREAM_INLINE ssize_t io_sock_stream_recv(io_sock_stream_t *sock,
		void *buf, size_t nbytes, int *flags, int timeout);

/**
 * Submits a receive operation to a stream socket. The completion task is
 * submitted for execution once one or more bytes have been received or an error
 * occurs.
 */
LELY_IO_SOCK_STREAM_INLINE void io_sock_stream_submit_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv);

/**
 * Cancels the specified stream socket receive operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_cancel_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv);

/**
 * Aborts the specified stream socket receive operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_abort_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv);

/**
 * Submits an asynchronous receive operation to a stream socket and creates a
 * future which becomes ready once the receive operation completes (or is
 * canceled). The result of the future has type #io_stream_result.
 *
 * @param sock   a pointer to a stream socket.
 * @param exec   a pointer to the executor used to execute the completion
 *               function of the receive operation. If NULL, the default
 *               executor of the stream socket is used.
 * @param buf    the address at which to store the bytes.
 * @param nbytes the number of bytes to receive.
 * @param flags  a pointer to the flags of the receive operation (on input, any
 *               combination of #IO_MSG_OOB and #IO_MSG_PEEK; on output,
 *               #IO_MSG_OOB may be set).
 * @param precv  the address at which to store a pointer to the receive
 *               operation (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_stream_async_recv(io_sock_stream_t *sock, ev_exec_t *exec,
		void *buf, size_t nbytes, int *flags,
		struct io_sock_stream_recv **precv);

/**
 * Equivalent to io_sock_stream_send(), except that the output data is gathered
 * from the <b>bufcnt</b> buffers specified by the members of the <b>buf</b>
 * array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_SOCK_STREAM_INLINE ssize_t io_sock_stream_sendmsg(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt,
		int flags, int timeout);

/**
 * Submits a vectored send operation to a stream socket. The completion task is
 * submitted for execution once the bytes have been sent or an error occurs.
 */
LELY_IO_SOCK_STREAM_INLINE void io_sock_stream_submit_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg);

/**
 * Cancels the specified vectored stream socket send operation if it is pending.
 * The completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_cancel_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg);

/**
 * Aborts the specified vectored stream socket send operation if it is pending.
 * If aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_abort_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg);

/**
 * Equivalent to io_sock_stream_async_send(), except that the output data is
 * gathered from the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_sock_stream_async_sendmsg(io_sock_stream_t *sock,
		ev_exec_t *exec, const struct io_buf *buf, int bufcnt,
		int flags, struct io_sock_stream_sendmsg **psendmsg);

/**
 * Initiates the transmission of a message from a stream socket to its peer as
 * if by POSIX `send()`. With <b>flags</b> = 0, this function is equivalent to
 * io_stream_write().
 *
 * @param sock    a pointer to a stream socket.
 * @param buf     a pointer to the bytes to be sent.
 * @param nbytes  the number of bytes to send.
 * @param flags   the flags of the send operation (any combination of
 *                #IO_MSG_DONTROUTE and #IO_MSG_OOB).
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns the number of bytes sent, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
LELY_IO_SOCK_STREAM_INLINE ssize_t io_sock_stream_send(io_sock_stream_t *sock,
		const void *buf, size_t nbytes, int flags, int timeout);

/**
 * Submits a send operation to a stream socket. The completion task is submitted
 * for execution once the bytes have been sent or an error occurs.
 */
LELY_IO_SOCK_STREAM_INLINE void io_sock_stream_submit_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send);

/**
 * Cancels the specified stream socket send operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_cancel_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send);

/**
 * Aborts the specified stream socket send operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_abort_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send);

/**
 * Submits an asynchronous send operation to a stream socket and creates a
 * future which becomes ready once the send operation completes (or is
 * canceled). The result of the future has type #io_stream_result.
 *
 * @param sock   a pointer to a stream socket.
 * @param exec   a pointer to the executor used to execute the completion
 *               function of the send operation. If NULL, the default executor
 *               of the stream socket is used.
 * @param buf    a pointer to the bytes to be sent.
 * @param nbytes the number of bytes to send.
 * @param flags  the flags of the send operation (any combination of
 *               #IO_MSG_DONTROUTE and #IO_MSG_OOB).
 * @param psend  the address at which to store a pointer to the send operation
 *               (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_stream_async_send(io_sock_stream_t *sock, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		struct io_sock_stream_send **psend);

/**
 * Shuts down all or part of full-duplex connection on a stream socket. This
 * function disables further send and/or receive operations, depending on the
 * value of <b>how</b>. Note that this function MAY block if the socket is
 * configured to linger and wait for a gracefull shutdown.
 *
 * @param sock a pointer to an open stream socket.
 * @param how  the type of shutdown (one of #IO_SHUT_RD, #IO_SHUT_WR or
 *             #IO_SHUT_RDWR).
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_shutdown(
		io_sock_stream_t *sock, int how);

/**
 * Checks whether periodic transmission of keep-alive messages is enabled.
 *
 * This option is equivalent to the SO_KEEPALIVE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 1 if keep-alive messages are enabled, 0 if not and -1 on error. In
 * the latter case, the error number can be obtained with get_errc().
 *
 * @see io_sock_stream_set_keepalive()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_get_keepalive(
		const io_sock_stream_t *sock);

/**
 * Enables periodic transmission of keep-alive messages. If <b>optval</b> is 1,
 * this option is enabled, and if the connected socket fails to respond to the
 * keep-alive messages, the connection shall be broken.
 *
 * This option is equivalent to the SO_KEEPALIVE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_stream_get_keepalive()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_set_keepalive(
		io_sock_stream_t *sock, int optval);

/**
 * Obtains the actions taken for queued, unsent data when a socket is closed
 * or a connection is shut down. If not NULL, *<b>ponoff</b> will be 0 if the
 * shutdown sequence is performed in the background and 1 otherwise. In the
 * latter case, *<b>plinger</b> (if not NULL), contains the linger time (in
 * seconds).
 *
 * This option is equivalent to the SO_LINGER option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_stream_set_linger()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_get_linger(
		const io_sock_stream_t *sock, int *ponoff, int *plinger);

/**
 * Specifies the actions taken for queued, unsent data when a socket is closed
 * or a connection is shut down. If <b>onoff</b> is 0, the shutdown sequence is
 * performed in the background. Otherwise, io_sock_stream_close() and
 * io_sock_stream_shutdown() MAY block untill all queued data has been sent or
 * <b>linger</b> seconds have elapsed.
 *
 * This option is equivalent to the SO_LINGER option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_stream_get_linger()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_set_linger(
		io_sock_stream_t *sock, int onoff, int linger);

/**
 * Checks whether out-of-band out-of-band (OOB) data is received in-line with
 * normal data.
 *
 * This option is equivalent to the SO_OOBINLINE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 1 if OOB data is placed into the normal data input queue, 0 if not
 * and -1 on error. In the latter case, the error number can be obtained with
 * get_errc().
 *
 * @see io_sock_stream_set_oobinline()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_get_oobinline(
		const io_sock_stream_t *sock);

/**
 * Specifies whether out-of-band out-of-band (OOB) data should be received
 * in-line with normal data. If <b>optval</b> is 1, OOB data is placed into the
 * normal data input queue. If not, it can only be received when the #IO_MSG_OOB
 * flag is set in a receive operaton. The presence of in-line OOB data can be
 * determined with io_sock_stream_atmark().
 *
 * This option is equivalent to the SO_OOBINLINE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_stream_get_oobinline()
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_set_oobinline(
		io_sock_stream_t *sock, int optval);

/**
 * Checks a socket is at the out-of-band mark as if by POSIX `sockatmark()`.
 *
 * @returns 1 if the socket is at the mark, 0 if not and -1 on error. In the
 * latter case, the error number can be obtained with get_errc().
 */
LELY_IO_SOCK_STREAM_INLINE int io_sock_stream_atmark(
		const io_sock_stream_t *sock);

/**
 * Obtains a pointer to a stream socket connect operation from a pointer to its
 * completion task.
 */
struct io_sock_stream_connect *io_sock_stream_connect_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a vectored stream socket receive operation from a
 * pointer to its completion task.
 */
struct io_sock_stream_recvmsg *io_sock_stream_recvmsg_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a stream socket receive operation from a pointer to its
 * completion task.
 */
struct io_sock_stream_recv *io_sock_stream_recv_from_task(struct ev_task *task);

/**
 * Obtains a pointer to a vectored stream socket send operation from a pointer
 * to its completion task.
 */
struct io_sock_stream_sendmsg *io_sock_stream_sendmsg_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a stream socket send operation from a pointer to its
 * completion task.
 */
struct io_sock_stream_send *io_sock_stream_send_from_task(struct ev_task *task);

static inline io_ctx_t *
io_sock_stream_get_ctx(const io_sock_stream_t *sock)
{
	return io_dev_get_ctx(io_sock_stream_get_dev(sock));
}

static inline ev_exec_t *
io_sock_stream_get_exec(const io_sock_stream_t *sock)
{
	return io_dev_get_exec(io_sock_stream_get_dev(sock));
}

static inline size_t
io_sock_stream_cancel(io_sock_stream_t *sock, struct ev_task *task)
{
	return io_dev_cancel(io_sock_stream_get_dev(sock), task);
}

static inline size_t
io_sock_stream_abort(io_sock_stream_t *sock, struct ev_task *task)
{
	return io_dev_abort(io_sock_stream_get_dev(sock), task);
}

static inline io_dev_t *
io_sock_stream_get_dev(const io_sock_stream_t *sock)
{
	return io_sock_get_dev(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_bind(io_sock_stream_t *sock, const struct io_endp *endp,
		int reuseaddr)
{
	return io_sock_bind(io_sock_stream_get_sock(sock), endp, reuseaddr);
}

static inline int
io_sock_stream_getsockname(const io_sock_stream_t *sock, struct io_endp *endp)
{
	return io_sock_getsockname(io_sock_stream_get_sock(sock), endp);
}

static inline int
io_sock_stream_is_open(const io_sock_stream_t *sock)
{
	return io_sock_is_open(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_close(io_sock_stream_t *sock)
{
	return io_sock_close(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_wait(io_sock_stream_t *sock, int *events, int timeout)
{
	return io_sock_wait(io_sock_stream_get_sock(sock), events, timeout);
}

static inline void
io_sock_stream_submit_wait(io_sock_stream_t *sock, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_sock_stream_get_sock(sock), wait);
}

static inline size_t
io_sock_stream_cancel_wait(io_sock_stream_t *sock, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_sock_stream_get_sock(sock), wait);
}

static inline size_t
io_sock_stream_abort_wait(io_sock_stream_t *sock, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_sock_stream_get_sock(sock), wait);
}

static inline ev_future_t *
io_sock_stream_async_wait(io_sock_stream_t *sock, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_sock_stream_get_sock(sock), exec, events, pwait);
}

static inline int
io_sock_stream_get_error(io_sock_stream_t *sock)
{
	return io_sock_get_error(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_get_nread(const io_sock_stream_t *sock)
{
	return io_sock_get_nread(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_get_dontroute(const io_sock_stream_t *sock)
{
	return io_sock_get_dontroute(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_set_dontroute(io_sock_stream_t *sock, int optval)
{
	return io_sock_set_dontroute(io_sock_stream_get_sock(sock), optval);
}

static inline int
io_sock_stream_get_rcvbuf(const io_sock_stream_t *sock)
{
	return io_sock_get_rcvbuf(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_set_rcvbuf(io_sock_stream_t *sock, int optval)
{
	return io_sock_set_rcvbuf(io_sock_stream_get_sock(sock), optval);
}

static inline int
io_sock_stream_get_sndbuf(const io_sock_stream_t *sock)
{
	return io_sock_get_sndbuf(io_sock_stream_get_sock(sock));
}

static inline int
io_sock_stream_set_sndbuf(io_sock_stream_t *sock, int optval)
{
	return io_sock_set_sndbuf(io_sock_stream_get_sock(sock), optval);
}

static inline ssize_t
io_sock_stream_readv(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt)
{
	return io_stream_readv(io_sock_stream_get_stream(sock), buf, bufcnt);
}

static inline void
io_sock_stream_submit_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv)
{
	io_stream_submit_readv(io_sock_stream_get_stream(sock), readv);
}

static inline size_t
io_sock_stream_cancel_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv)
{
	return io_stream_cancel_readv(io_sock_stream_get_stream(sock), readv);
}

static inline size_t
io_sock_stream_abort_readv(
		io_sock_stream_t *sock, struct io_stream_readv *readv)
{
	return io_stream_abort_readv(io_sock_stream_get_stream(sock), readv);
}

static inline ev_future_t *
io_sock_stream_async_readv(io_sock_stream_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv)
{
	return io_stream_async_readv(io_sock_stream_get_stream(sock), exec, buf,
			bufcnt, preadv);
}

static inline ssize_t
io_sock_stream_read(io_sock_stream_t *sock, void *buf, size_t nbytes)
{
	return io_stream_read(io_sock_stream_get_stream(sock), buf, nbytes);
}

static inline void
io_sock_stream_submit_read(io_sock_stream_t *sock, struct io_stream_read *read)
{
	io_stream_submit_read(io_sock_stream_get_stream(sock), read);
}

static inline size_t
io_sock_stream_cancel_read(io_sock_stream_t *sock, struct io_stream_read *read)
{
	return io_stream_cancel_read(io_sock_stream_get_stream(sock), read);
}

static inline size_t
io_sock_stream_abort_read(io_sock_stream_t *sock, struct io_stream_read *read)
{
	return io_stream_abort_read(io_sock_stream_get_stream(sock), read);
}

static inline ev_future_t *
io_sock_stream_async_read(io_sock_stream_t *sock, ev_exec_t *exec, void *buf,
		size_t nbytes, struct io_stream_read **pread)
{
	return io_stream_async_read(io_sock_stream_get_stream(sock), exec, buf,
			nbytes, pread);
}

static inline ssize_t
io_sock_stream_writev(
		io_sock_stream_t *sock, const struct io_buf *buf, int bufcnt)
{
	return io_stream_writev(io_sock_stream_get_stream(sock), buf, bufcnt);
}

static inline void
io_sock_stream_submit_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev)
{
	io_stream_submit_writev(io_sock_stream_get_stream(sock), writev);
}

static inline size_t
io_sock_stream_cancel_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev)
{
	return io_stream_cancel_writev(io_sock_stream_get_stream(sock), writev);
}

static inline size_t
io_sock_stream_abort_writev(
		io_sock_stream_t *sock, struct io_stream_writev *writev)
{
	return io_stream_abort_writev(io_sock_stream_get_stream(sock), writev);
}

static inline ev_future_t *
io_sock_stream_async_writev(io_sock_stream_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev)
{
	return io_stream_async_writev(io_sock_stream_get_stream(sock), exec,
			buf, bufcnt, pwritev);
}

static inline ssize_t
io_sock_stream_write(io_sock_stream_t *sock, const void *buf, size_t nbytes)
{
	return io_stream_write(io_sock_stream_get_stream(sock), buf, nbytes);
}

static inline void
io_sock_stream_submit_write(
		io_sock_stream_t *sock, struct io_stream_write *write)
{
	io_stream_submit_write(io_sock_stream_get_stream(sock), write);
}

static inline size_t
io_sock_stream_cancel_write(
		io_sock_stream_t *sock, struct io_stream_write *write)
{
	return io_stream_cancel_write(io_sock_stream_get_stream(sock), write);
}

static inline size_t
io_sock_stream_abort_write(
		io_sock_stream_t *sock, struct io_stream_write *write)
{
	return io_stream_abort_write(io_sock_stream_get_stream(sock), write);
}

static inline ev_future_t *
io_sock_stream_async_write(io_sock_stream_t *sock, ev_exec_t *exec,
		const void *buf, size_t nbytes, struct io_stream_write **pwrite)
{
	return io_stream_async_write(io_sock_stream_get_stream(sock), exec, buf,
			nbytes, pwrite);
}

inline io_sock_t *
io_sock_stream_get_sock(const io_sock_stream_t *sock)
{
	return (*sock)->get_sock(sock);
}

inline io_stream_t *
io_sock_stream_get_stream(const io_sock_stream_t *sock)
{
	return (*sock)->get_stream(sock);
}

inline int
io_sock_stream_getpeername(const io_sock_stream_t *sock, struct io_endp *endp)
{
	return (*sock)->getpeername(sock, endp);
}

inline int
io_sock_stream_connect(io_sock_stream_t *sock, const struct io_endp *endp)
{
	return (*sock)->connect(sock, endp);
}

inline void
io_sock_stream_submit_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect)
{
	(*sock)->submit_connect(sock, connect);
}

static inline size_t
io_sock_stream_cancel_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_cancel(sock, &connect->task);
}

static inline size_t
io_sock_stream_abort_connect(
		io_sock_stream_t *sock, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_abort(sock, &connect->task);
}

inline ssize_t
io_sock_stream_recvmsg(io_sock_stream_t *sock, const struct io_buf *buf,
		int bufcnt, int *flags, int timeout)
{
	return (*sock)->recvmsg(sock, buf, bufcnt, flags, timeout);
}

inline void
io_sock_stream_submit_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg)
{
	(*sock)->submit_recvmsg(sock, recvmsg);
}

static inline size_t
io_sock_stream_cancel_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_cancel(sock, &recvmsg->task);
}

static inline size_t
io_sock_stream_abort_recvmsg(
		io_sock_stream_t *sock, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_abort(sock, &recvmsg->task);
}

inline ssize_t
io_sock_stream_recv(io_sock_stream_t *sock, void *buf, size_t nbytes,
		int *flags, int timeout)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_sock_stream_recvmsg(sock, buf_, 1, flags, timeout);
}

inline void
io_sock_stream_submit_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv)
{
	io_sock_stream_submit_recvmsg(sock, &recv->recvmsg);
}

static inline size_t
io_sock_stream_cancel_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_cancel_recvmsg(sock, &recv->recvmsg);
}

static inline size_t
io_sock_stream_abort_recv(
		io_sock_stream_t *sock, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_abort_recvmsg(sock, &recv->recvmsg);
}

inline ssize_t
io_sock_stream_sendmsg(io_sock_stream_t *sock, const struct io_buf *buf,
		int bufcnt, int flags, int timeout)
{
	return (*sock)->sendmsg(sock, buf, bufcnt, flags, timeout);
}

inline void
io_sock_stream_submit_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg)
{
	(*sock)->submit_sendmsg(sock, sendmsg);
}

static inline size_t
io_sock_stream_cancel_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_cancel(sock, &sendmsg->task);
}

static inline size_t
io_sock_stream_abort_sendmsg(
		io_sock_stream_t *sock, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_abort(sock, &sendmsg->task);
}

inline ssize_t
io_sock_stream_send(io_sock_stream_t *sock, const void *buf, size_t nbytes,
		int flags, int timeout)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_sock_stream_sendmsg(sock, buf_, 1, flags, timeout);
}

inline void
io_sock_stream_submit_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send)
{
	io_sock_stream_submit_sendmsg(sock, &send->sendmsg);
}

static inline size_t
io_sock_stream_cancel_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send)
{
	return io_sock_stream_cancel_sendmsg(sock, &send->sendmsg);
}

static inline size_t
io_sock_stream_abort_send(
		io_sock_stream_t *sock, struct io_sock_stream_send *send)
{
	return io_sock_stream_abort_sendmsg(sock, &send->sendmsg);
}

inline int
io_sock_stream_shutdown(io_sock_stream_t *sock, int type)
{
	return (*sock)->shutdown(sock, type);
}

inline int
io_sock_stream_get_keepalive(const io_sock_stream_t *sock)
{
	return (*sock)->get_keepalive(sock);
}

inline int
io_sock_stream_set_keepalive(io_sock_stream_t *sock, int optval)
{
	return (*sock)->set_keepalive(sock, optval);
}

inline int
io_sock_stream_get_linger(
		const io_sock_stream_t *sock, int *ponoff, int *plinger)
{
	return (*sock)->get_linger(sock, ponoff, plinger);
}

inline int
io_sock_stream_set_linger(io_sock_stream_t *sock, int onoff, int linger)
{
	return (*sock)->set_linger(sock, onoff, linger);
}

inline int
io_sock_stream_get_oobinline(const io_sock_stream_t *sock)
{
	return (*sock)->get_oobinline(sock);
}

inline int
io_sock_stream_set_oobinline(io_sock_stream_t *sock, int optval)
{
	return (*sock)->set_oobinline(sock, optval);
}

inline int
io_sock_stream_atmark(const io_sock_stream_t *sock)
{
	return (*sock)->atmark(sock);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SOCK_STREAM_H_
