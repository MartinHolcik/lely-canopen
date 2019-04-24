/**@file
 * This header file is part of the I/O library; it contains the abstract
 * datagram socket interface.
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

#ifndef LELY_IO2_SOCK_DGRAM_H_
#define LELY_IO2_SOCK_DGRAM_H_

#include <lely/io2/buf.h>
#include <lely/io2/sock.h>
#include <lely/libc/sys/types.h>

#ifndef LELY_IO_SOCK_DGRAM_INLINE
#define LELY_IO_SOCK_DGRAM_INLINE static inline
#endif

/// An abstract datagram socket.
typedef const struct io_sock_dgram_vtbl *const io_sock_dgram_t;

/// The result of read or write operation on a datagram socket.
struct io_dgram_result {
	/**
	 * The number of bytes sent or received, or -1 on error (or if the
	 * operation is canceled). In the latter case, the error number is
	 * stored in #errc.
	 */
	ssize_t result;
	/// The error number, obtained as if by get_errc(), if #result is -1.
	int errc;
};

/**
 * A vectored datagram socket receive operation. The operation is performed as
 * if by POSIX `recvmsg()`.
 */
struct io_sock_dgram_recvmsg {
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
	 * The flags of the receive operation (on input, may be #IO_MSG_PEEK; on
	 * output, #IO_MSG_EOR and #IO_MSG_TRUNC may be set).
	 */
	int flags;
	/**
	 * The address at which to store the sending network protocol endpoint.
	 * If not NULL, it is the responsibility of the user to ensure the
	 * endpoint matches the address family and protocol of the socket and
	 * remains valid until the operation completes.
	 */
	struct io_endp *endp;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_dgram_result r;
#if _WIN32
	// The socket handle passed to `WSAGetOverlappedResult()`.
	void *_handle;
	// The buffer in which the sending address is stored.
	struct io_sockaddr_storage _addr;
	// The length (in bytes) if the sending address.
	int _addrlen;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_dgram_recvmsg.
#if _WIN32
#define IO_SOCK_DGRAM_RECVMSG_INIT(buf, bufcnt, flags, endp, exec, func) \
	{ \
		(buf), (bufcnt), (flags), (endp), EV_TASK_INIT(exec, func), \
				{ 0, 0 }, INVALID_HANDLE_VALUE, \
				IO_SOCKADDR_STORAGE_INIT, 0, IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_DGRAM_RECVMSG_INIT(buf, bufcnt, flags, endp, exec, func) \
	{ \
		(buf), (bufcnt), (flags), (endp), EV_TASK_INIT(exec, func), \
		{ \
			0, 0 \
		} \
	}
#endif

/**
 * A datagram socket receive operation. The operation is performed as if by
 * POSIX `recvfrom()`.
 */
struct io_sock_dgram_recvfrom {
	/// The vectored receive operation.
	struct io_sock_dgram_recvmsg recvmsg;
	/// The receive buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_sock_dgram_recvfrom. <b>self</b> MUST be the
 * address of the struct being initialized.
 */
#define IO_SOCK_DGRAM_RECVFROM_INIT(self, base, len, flags, endp, exec, func) \
	{ \
		IO_SOCK_DGRAM_RECVMSG_INIT((self)->buf, 1, (flags), (endp), \
				(exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

/**
 * A vectored datagram socket send operation. The operation is performed as if
 * by POSIX `sendmsg()`.
 */
struct io_sock_dgram_sendmsg {
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
	 * and #IO_MSG_EOR).
	 */
	int flags;
	/**
	 * A pointer to the destination network protocol endpoint (can be NULL
	 * after a successful call to io_sock_dgram_connect()). If not NULL, it
	 * is the responsibility of the user to ensure the endpoint matches the
	 * address family and protocol of the socket and remains valid until the
	 * operation completes.
	 */
	const struct io_endp *endp;
	/**
	 * The task (to be) submitted upon completion (or cancellation) of the
	 * operation.
	 */
	struct ev_task task;
	/// The result of the operation.
	struct io_dgram_result r;
#if _WIN32
	// The socket handle passed to `WSAGetOverlappedResult()`.
	void *_handle;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_dgram_sendmsg.
#if _WIN32
#define IO_SOCK_DGRAM_SENDMSG_INIT(buf, bufcnt, flags, endp, exec, func) \
	{ \
		(buf), (bufcnt), (flags), (endp), EV_TASK_INIT(exec, func), \
				{ 0, 0 }, INVALID_HANDLE_VALUE, \
				IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_DGRAM_SENDMSG_INIT(buf, bufcnt, flags, endp, exec, func) \
	{ \
		(buf), (bufcnt), (flags), (endp), EV_TASK_INIT(exec, func), \
		{ \
			0, 0 \
		} \
	}
#endif

/**
 * A datagram socket send operation. The operation is performed as if by POSIX
 * `sendto()`.
 */
struct io_sock_dgram_sendto {
	/// The vectored send operation.
	struct io_sock_dgram_sendmsg sendmsg;
	/// The send buffer.
	struct io_buf buf[1];
};

/**
 * The static initializer for #io_sock_dgram_sendto. <b>self</b> MUST be the
 * address of the struct being initialized.
 */
#define IO_SOCK_DGRAM_SENDTO_INIT(self, base, len, flags, endp, exec, func) \
	{ \
		IO_SOCK_DGRAM_SENDMSG_INIT((self)->buf, 1, (flags), (endp), \
				(exec), (func)), \
		{ \
			IO_BUF_INIT(base, len) \
		} \
	}

#ifdef __cplusplus
extern "C" {
#endif

struct io_sock_dgram_vtbl {
	io_sock_t *(*get_sock)(const io_sock_dgram_t *sock);
	int (*connect)(io_sock_dgram_t *sock, const struct io_endp *endp);
	int (*getpeername)(const io_sock_dgram_t *sock, struct io_endp *endp);
	ssize_t (*recvmsg)(io_sock_dgram_t *sock, const struct io_buf *buf,
			int bufcnt, int *flags, struct io_endp *endp,
			int timeout);
	void (*submit_recvmsg)(io_sock_dgram_t *sock,
			struct io_sock_dgram_recvmsg *recvmsg);
	ssize_t (*sendmsg)(io_sock_dgram_t *sock, const struct io_buf *buf,
			int bufcnt, int flags, const struct io_endp *endp,
			int timeout);
	void (*submit_sendmsg)(io_sock_dgram_t *sock,
			struct io_sock_dgram_sendmsg *sendmsg);
	int (*get_broadcast)(const io_sock_dgram_t *sock);
	int (*set_broadcast)(io_sock_dgram_t *sock, int optval);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_sock_dgram_get_ctx(const io_sock_dgram_t *sock);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_sock_dgram_get_exec(const io_sock_dgram_t *sock);

/// @see io_dev_cancel()
static inline size_t io_sock_dgram_cancel(
		io_sock_dgram_t *sock, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_sock_dgram_abort(
		io_sock_dgram_t *sock, struct ev_task *task);

/// @see io_sock_get_dev()
static inline io_dev_t *io_sock_dgram_get_dev(const io_sock_dgram_t *sock);

/// @see io_sock_bind()
static inline int io_sock_dgram_bind(io_sock_dgram_t *sock,
		const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_sock_dgram_getsockname(
		const io_sock_dgram_t *sock, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_sock_dgram_is_open(const io_sock_dgram_t *sock);

/// @see io_sock_close()
static inline int io_sock_dgram_close(io_sock_dgram_t *sock);

/// @see io_sock_wait()
static inline int io_sock_dgram_wait(
		io_sock_dgram_t *sock, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_sock_dgram_submit_wait(
		io_sock_dgram_t *sock, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_sock_dgram_cancel_wait(
		io_sock_dgram_t *sock, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_sock_dgram_abort_wait(
		io_sock_dgram_t *sock, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_sock_dgram_async_wait(io_sock_dgram_t *sock,
		ev_exec_t *exec, int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_sock_dgram_get_error(io_sock_dgram_t *sock);

/// @see io_sock_get_nread()
static inline int io_sock_dgram_get_nread(const io_sock_dgram_t *sock);

/// @see io_sock_get_dontroute()
static inline int io_sock_dgram_get_dontroute(const io_sock_dgram_t *sock);

/// @see io_sock_set_dontroute()
static inline int io_sock_dgram_set_dontroute(
		io_sock_dgram_t *sock, int optval);

/// @see io_sock_get_rcvbuf()
static inline int io_sock_dgram_get_rcvbuf(const io_sock_dgram_t *sock);

/// @see io_sock_set_rcvbuf()
static inline int io_sock_dgram_set_rcvbuf(io_sock_dgram_t *sock, int optval);

/// @see io_sock_get_sndbuf()
static inline int io_sock_dgram_get_sndbuf(const io_sock_dgram_t *sock);

/// @see io_sock_set_sndbuf()
static inline int io_sock_dgram_set_sndbuf(io_sock_dgram_t *sock, int optval);

/// Returns a pointer to the abstract socket representing the datagram socket.
LELY_IO_SOCK_DGRAM_INLINE io_sock_t *io_sock_dgram_get_sock(
		const io_sock_dgram_t *sock);

/**
 * Sets the destination network protocol endpoint of a datagram socket. Once
 * set, subsequent send operations can omit the destination. If <b>endp</b> is
 * NULL, the destination is reset.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * cann be obtained with get_errc().
 *
 * @see io_sock_dgram_getpeername()
 */
LELY_IO_SOCK_DGRAM_INLINE int io_sock_dgram_connect(
		io_sock_dgram_t *sock, const struct io_endp *endp);

/**
 * Obtains the destination network protocol endpoint of a datagram socket.
 *
 * @param sock a pointer to a datagram socket.
 * @param sock a pointer to a stream socket.
 * @param endp the address at which to store the endpoint. If not NULL, it is
 *             the responsibility of the user to ensure the endpoint matches the
 *             address family and protocol of the socket.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_dgram_connect()
 */
LELY_IO_SOCK_DGRAM_INLINE int io_sock_dgram_getpeername(
		const io_sock_dgram_t *sock, struct io_endp *endp);

/**
 * Equivalent to io_sock_dgram_recvfrom(), except that the input data is
 * scattered into the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_SOCK_DGRAM_INLINE ssize_t io_sock_dgram_recvmsg(io_sock_dgram_t *sock,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, int timeout);

/**
 * Submits a vectored receive operation to a datagram socket. The completion
 * task is submitted for execution once one a datagram has been received or
 * an error occurs.
 */
LELY_IO_SOCK_DGRAM_INLINE void io_sock_dgram_submit_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg);

/**
 * Cancels the specified vectored datagram socket receive operation if it is
 * pending. The completion task is submitted for execution with
 * <b>result</b> = -1 and <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_dgram_cancel_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg);

/**
 * Aborts the specified vectored datagram socket receive operation if it is
 * pending. If aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_dgram_abort_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg);

/**
 * Equivalent to io_sock_dgram_async_recvfrom(), except that the input data is
 * scattered into the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_sock_dgram_async_recvmsg(io_sock_dgram_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, struct io_sock_dgram_recvmsg **precvmsg);

/**
 * Receives a message from a datagram socket as if by POSIX `recvfrom()`.
 *
 * @param sock    a pointer to a datagram socket.
 * @param buf     the address at which to store the bytes.
 * @param nbytes  the number of bytes to receive.
 * @param flags   a pointer to the flags of the receive operation (on input,
 *                #IO_MSG_PEEK may be set; on output, #IO_MSG_EOR and
 *                #IO_MSG_TRUNC may be set).
 * @param endp    the address at which to store the sending network protocol
 *                endpoint. If not NULL, it is the responsibility of the user to
 *                ensure the endpoint matches the address family and protocol of
 *                the socket.
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns the number of bytes received on success, or -1 on error. In the
 * latter case, the error number can be obtained with get_errc().
 */
LELY_IO_SOCK_DGRAM_INLINE ssize_t io_sock_dgram_recvfrom(io_sock_dgram_t *sock,
		void *buf, size_t nbytes, int *flags, struct io_endp *endp,
		int timeout);

/**
 * Submits a receive operation to a datagram socket. The completion task is
 * submitted for execution once a datagram has been received or an error occurs.
 */
LELY_IO_SOCK_DGRAM_INLINE void io_sock_dgram_submit_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom);

/**
 * Cancels the specified datagram socket receive operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_dgram_cancel_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom);

/**
 * Aborts the specified datagram socket receive operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_dgram_abort_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom);

/**
 * Submits an asynchronous receive operation to a datagram socket and creates a
 * future which becomes ready once the receive operation completes (or is
 * canceled). The result of the future has type #io_dgram_result.
 *
 * @param sock      a pointer to a datagram socket.
 * @param exec      a pointer to the executor used to execute the completion
 *                  function of the receive operation. If NULL, the default
 *                  executor of the datagram socket is used.
 * @param buf       the address at which to store the bytes.
 * @param nbytes    the number of bytes to receive.
 * @param flags     a pointer to the flags of the receive operation (on input,
 *                  #IO_MSG_PEEK may be set; on output, #IO_MSG_EOR and
 *                  #IO_MSG_TRUNC may be set).
 * @param endp      the address at which to store the sending network protocol
 *                  endpoint. If not NULL, it is the responsibility of the user
 *                  to ensure the endpoint matches the address family and
 *                  protocol of the socket.
 * @param precvfrom the address at which to store a pointer to the receive
 *                  operation (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_dgram_async_recvfrom(io_sock_dgram_t *sock,
		ev_exec_t *exec, void *buf, size_t nbytes, int *flags,
		struct io_endp *endp,
		struct io_sock_dgram_recvfrom **precvfrom);

/**
 * Equivalent to io_sock_dgram_sendto(), except that the output data is gathered
 * from the <b>bufcnt</b> buffers specified by the members of the <b>buf</b>
 * array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
LELY_IO_SOCK_DGRAM_INLINE ssize_t io_sock_dgram_sendmsg(io_sock_dgram_t *sock,
		const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp, int timeout);

/**
 * Submits a vectored send operation to a datagram socket. The completion task
 * is submitted for execution once the bytes have been sent or an error occurs.
 */
LELY_IO_SOCK_DGRAM_INLINE void io_sock_dgram_submit_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg);

/**
 * Cancels the specified vectored datagram socket send operation if it is
 * pending. The completion task is submitted for execution with <b>result</b> =
 * -1 and <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_dgram_cancel_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg);

/**
 * Aborts the specified vectored datagram socket send operation if it is
 * pending. If aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_dgram_abort_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg);

/**
 * Equivalent to io_sock_dgram_async_sendto(), except that the output data is
 * gathered from the <b>bufcnt</b> buffers specified by the members of the
 * <b>buf</b> array. The <b>bufcnt</b> argument MUST be positive and MAY have an
 * implementation-defined upper limit.
 */
ev_future_t *io_sock_dgram_async_sendmsg(io_sock_dgram_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendmsg **psendmsg);

/**
 * Initiates the transmission of a message from a datagram socket as if by POSIX
 * `sendto()`.
 *
 * @param sock    a pointer to a datagram socket.
 * @param buf     a pointer to the bytes to be sent.
 * @param nbytes  the number of bytes to send.
 * @param flags   the flags of the send operation (any combination of
 *                #IO_MSG_DONTROUTE and #IO_MSG_EOR).
 * @param endp    a pointer to the destination network protocol endpoint (can be
 *                NULL after a successful call to io_sock_dgram_connect()). If
 *                not NULL, it is the responsibility of the user to ensure the
 *                endpoint matches the address family and protocol of the
 *                socket.
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns the number of bytes sent, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
LELY_IO_SOCK_DGRAM_INLINE ssize_t io_sock_dgram_sendto(io_sock_dgram_t *sock,
		const void *buf, size_t nbytes, int flags,
		const struct io_endp *endp, int timeout);

/**
 * Submits a send operation to a datagram socket. The completion task is
 * submitted for execution once the datagram has been sent or an error occurs.
 */
LELY_IO_SOCK_DGRAM_INLINE void io_sock_dgram_submit_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto);

/**
 * Cancels the specified datagram socket send operation if it is pending. The
 * completion task is submitted for execution with <b>result</b> = -1 and
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_dgram_cancel_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto);

/**
 * Aborts the specified datagram socket send operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_dgram_abort_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto);

/**
 * Submits an asynchronous send operation to a datagram socket and creates a
 * future which becomes ready once the send operation completes (or is
 * canceled). The result of the future has type #io_dgram_result.
 *
 * @param sock    a pointer to a datagram socket.
 * @param exec    a pointer to the executor used to execute the completion
 *                function of the send operation. If NULL, the default executor
 *                of the datagram socket is used.
 * @param buf     a pointer to the bytes to be sent.
 * @param nbytes  the number of bytes to send.
 * @param flags   the flags of the send operation (any combination of
 *                #IO_MSG_DONTROUTE and #IO_MSG_EOR).
 * @param endp    a pointer to the destination network protocol endpoint (can be
 *                NULL after a successful call to io_sock_dgram_connect()). If
 *                not NULL, it is the responsibility of the user to ensure the
 *                endpoint matches the address family and protocol of the
 *                socket.
 * @param psendto the address at which to store a pointer to the send operation
 *                (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_dgram_async_sendto(io_sock_dgram_t *sock, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendto **psendto);

/**
 * Checks whether a socket has permission to send broadcast datagrams.
 *
 * This option is equivalent to the SO_BROADCAST option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 1 if the socket has permission to send broadcast datagrams, 0 if not
 * and -1 on error. In the latter case, the error number can be obtained with
 * get_errc().
 *
 * @see io_sock_dgram_set_broadcast()
 */
LELY_IO_SOCK_DGRAM_INLINE int io_sock_dgram_get_broadcast(
		const io_sock_dgram_t *sock);

/**
 * Enables or disables the broadcast flag. If <b>optval</b> is 1, the socket has
 * permission to send broadcast datagrams.
 *
 * This option is equivalent to the SO_BROADCAST option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_dgram_get_broadcast()
 */
LELY_IO_SOCK_DGRAM_INLINE int io_sock_dgram_set_broadcast(
		io_sock_dgram_t *sock, int optval);

/**
 * Obtains a pointer to a vectored datagram socket receive operation from a
 * pointer to its completion task.
 */
struct io_sock_dgram_recvmsg *io_sock_dgram_recvmsg_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a datagram socket receive operation from a pointer to
 * its completion task.
 */
struct io_sock_dgram_recvfrom *io_sock_dgram_recvfrom_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a vectored datagram socket send operation from a pointer
 * to its completion task.
 */
struct io_sock_dgram_sendmsg *io_sock_dgram_sendmsg_from_task(
		struct ev_task *task);

/**
 * Obtains a pointer to a datagram socket send operation from a pointer to its
 * completion task.
 */
struct io_sock_dgram_sendto *io_sock_dgram_sendto_from_task(
		struct ev_task *task);

static inline io_ctx_t *
io_sock_dgram_get_ctx(const io_sock_dgram_t *sock)
{
	return io_dev_get_ctx(io_sock_dgram_get_dev(sock));
}

static inline ev_exec_t *
io_sock_dgram_get_exec(const io_sock_dgram_t *sock)
{
	return io_dev_get_exec(io_sock_dgram_get_dev(sock));
}

static inline size_t
io_sock_dgram_cancel(io_sock_dgram_t *sock, struct ev_task *task)
{
	return io_dev_cancel(io_sock_dgram_get_dev(sock), task);
}

static inline size_t
io_sock_dgram_abort(io_sock_dgram_t *sock, struct ev_task *task)
{
	return io_dev_abort(io_sock_dgram_get_dev(sock), task);
}

static inline io_dev_t *
io_sock_dgram_get_dev(const io_sock_dgram_t *sock)
{
	return io_sock_get_dev(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_bind(io_sock_dgram_t *sock, const struct io_endp *endp,
		int reuseaddr)
{
	return io_sock_bind(io_sock_dgram_get_sock(sock), endp, reuseaddr);
}

static inline int
io_sock_dgram_getsockname(const io_sock_dgram_t *sock, struct io_endp *endp)
{
	return io_sock_getsockname(io_sock_dgram_get_sock(sock), endp);
}

static inline int
io_sock_dgram_is_open(const io_sock_dgram_t *sock)
{
	return io_sock_is_open(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_close(io_sock_dgram_t *sock)
{
	return io_sock_close(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_wait(io_sock_dgram_t *sock, int *events, int timeout)
{
	return io_sock_wait(io_sock_dgram_get_sock(sock), events, timeout);
}

static inline void
io_sock_dgram_submit_wait(io_sock_dgram_t *sock, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_sock_dgram_get_sock(sock), wait);
}

static inline size_t
io_sock_dgram_cancel_wait(io_sock_dgram_t *sock, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_sock_dgram_get_sock(sock), wait);
}

static inline size_t
io_sock_dgram_abort_wait(io_sock_dgram_t *sock, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_sock_dgram_get_sock(sock), wait);
}

static inline ev_future_t *
io_sock_dgram_async_wait(io_sock_dgram_t *sock, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_sock_dgram_get_sock(sock), exec, events, pwait);
}

static inline int
io_sock_dgram_get_error(io_sock_dgram_t *sock)
{
	return io_sock_get_error(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_get_nread(const io_sock_dgram_t *sock)
{
	return io_sock_get_nread(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_get_dontroute(const io_sock_dgram_t *sock)
{
	return io_sock_get_dontroute(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_set_dontroute(io_sock_dgram_t *sock, int optval)
{
	return io_sock_set_dontroute(io_sock_dgram_get_sock(sock), optval);
}

static inline int
io_sock_dgram_get_rcvbuf(const io_sock_dgram_t *sock)
{
	return io_sock_get_rcvbuf(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_set_rcvbuf(io_sock_dgram_t *sock, int optval)
{
	return io_sock_set_rcvbuf(io_sock_dgram_get_sock(sock), optval);
}

static inline int
io_sock_dgram_get_sndbuf(const io_sock_dgram_t *sock)
{
	return io_sock_get_sndbuf(io_sock_dgram_get_sock(sock));
}

static inline int
io_sock_dgram_set_sndbuf(io_sock_dgram_t *sock, int optval)
{
	return io_sock_set_sndbuf(io_sock_dgram_get_sock(sock), optval);
}

inline io_sock_t *
io_sock_dgram_get_sock(const io_sock_dgram_t *sock)
{
	return (*sock)->get_sock(sock);
}

inline int
io_sock_dgram_getpeername(const io_sock_dgram_t *sock, struct io_endp *endp)
{
	return (*sock)->getpeername(sock, endp);
}

inline int
io_sock_dgram_connect(io_sock_dgram_t *sock, const struct io_endp *endp)
{
	return (*sock)->connect(sock, endp);
}

inline ssize_t
io_sock_dgram_recvmsg(io_sock_dgram_t *sock, const struct io_buf *buf,
		int bufcnt, int *flags, struct io_endp *endp, int timeout)
{
	return (*sock)->recvmsg(sock, buf, bufcnt, flags, endp, timeout);
}

inline void
io_sock_dgram_submit_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg)
{
	(*sock)->submit_recvmsg(sock, recvmsg);
}

static inline size_t
io_sock_dgram_cancel_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg)
{
	return io_sock_dgram_cancel(sock, &recvmsg->task);
}

static inline size_t
io_sock_dgram_abort_recvmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvmsg *recvmsg)
{
	return io_sock_dgram_abort(sock, &recvmsg->task);
}

inline ssize_t
io_sock_dgram_recvfrom(io_sock_dgram_t *sock, void *buf, size_t nbytes,
		int *flags, struct io_endp *endp, int timeout)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_sock_dgram_recvmsg(sock, buf_, 1, flags, endp, timeout);
}

inline void
io_sock_dgram_submit_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom)
{
	io_sock_dgram_submit_recvmsg(sock, &recvfrom->recvmsg);
}

static inline size_t
io_sock_dgram_cancel_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom)
{
	return io_sock_dgram_cancel_recvmsg(sock, &recvfrom->recvmsg);
}

static inline size_t
io_sock_dgram_abort_recvfrom(
		io_sock_dgram_t *sock, struct io_sock_dgram_recvfrom *recvfrom)
{
	return io_sock_dgram_abort_recvmsg(sock, &recvfrom->recvmsg);
}

inline ssize_t
io_sock_dgram_sendmsg(io_sock_dgram_t *sock, const struct io_buf *buf,
		int bufcnt, int flags, const struct io_endp *endp, int timeout)
{
	return (*sock)->sendmsg(sock, buf, bufcnt, flags, endp, timeout);
}

inline void
io_sock_dgram_submit_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg)
{
	(*sock)->submit_sendmsg(sock, sendmsg);
}

static inline size_t
io_sock_dgram_cancel_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg)
{
	return io_sock_dgram_cancel(sock, &sendmsg->task);
}

static inline size_t
io_sock_dgram_abort_sendmsg(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendmsg *sendmsg)
{
	return io_sock_dgram_abort(sock, &sendmsg->task);
}

inline ssize_t
io_sock_dgram_sendto(io_sock_dgram_t *sock, const void *buf, size_t nbytes,
		int flags, const struct io_endp *endp, int timeout)
{
	struct io_buf buf_[1] = { IO_BUF_INIT(buf, nbytes) };
	return io_sock_dgram_sendmsg(sock, buf_, 1, flags, endp, timeout);
}

inline void
io_sock_dgram_submit_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto)
{
	io_sock_dgram_submit_sendmsg(sock, &sendto->sendmsg);
}

static inline size_t
io_sock_dgram_cancel_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto)
{
	return io_sock_dgram_cancel_sendmsg(sock, &sendto->sendmsg);
}

static inline size_t
io_sock_dgram_abort_sendto(
		io_sock_dgram_t *sock, struct io_sock_dgram_sendto *sendto)
{
	return io_sock_dgram_abort_sendmsg(sock, &sendto->sendmsg);
}

inline int
io_sock_dgram_get_broadcast(const io_sock_dgram_t *sock)
{
	return (*sock)->get_broadcast(sock);
}

inline int
io_sock_dgram_set_broadcast(io_sock_dgram_t *sock, int optval)
{
	return (*sock)->set_broadcast(sock, optval);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SOCK_DGRAM_H_
