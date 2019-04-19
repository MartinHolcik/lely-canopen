/**@file
 * This header file is part of the I/O library; it contains the abstract socket
 * interface.
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

#ifndef LELY_IO2_SOCK_H_
#define LELY_IO2_SOCK_H_

#include <lely/ev/future.h>
#include <lely/ev/task.h>
#include <lely/io2/dev.h>
#include <lely/io2/endp.h>
#include <lely/io2/event.h>
#if _WIN32
#include <lely/io2/win32/poll.h>
#endif

#include <limits.h>

#ifndef LELY_IO_SOCK_INLINE
#define LELY_IO_SOCK_INLINE static inline
#endif

/// An abstract socket.
typedef const struct io_sock_vtbl *const io_sock_t;

/// A wait operation for socket I/O events.
struct io_sock_wait {
	/**
	 * On input; the I/O events to monitor (any combination of #IO_EVENT_IN,
	 * #IO_EVENT_PRI, #IO_EVENT_OUT, #IO_EVENT_ERR and #IO_EVENT_HUP); on
	 * output, the reported I/O events. Note that #IO_EVENT_ERR and
	 * #IO_EVENT_HUP MAY be reported even if not monitored.
	 */
	int events;
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
	// The opaque AFD poll information struct.
	AFD_POLL_INFO _info;
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_wait.
#if _WIN32
#define IO_SOCK_WAIT_INIT(events, exec, func) \
	{ \
		(events), EV_TASK_INIT(exec, func), 0, \
				{ { { ULONG_MAX, LONG_MAX } }, 1, 0, \
					{ { INVALID_HANDLE_VALUE, 0, 0 } } }, \
				IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_WAIT_INIT(events, exec, func) \
	{ \
		(events), EV_TASK_INIT(exec, func), 0 \
	}
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct io_sock_vtbl {
	io_dev_t *(*get_dev)(const io_sock_t *sock);
	int (*bind)(io_sock_t *sock, const struct io_endp *endp, int reuseaddr);
	int (*getsockname)(const io_sock_t *sock, struct io_endp *endp);
	int (*is_open)(const io_sock_t *sock);
	int (*close)(io_sock_t *sock);
	int (*wait)(io_sock_t *sock, int *events, int timeout);
	void (*submit_wait)(io_sock_t *sock, struct io_sock_wait *wait);
	int (*get_error)(io_sock_t *sock);
	int (*get_nread)(const io_sock_t *sock);
	int (*get_dontroute)(const io_sock_t *sock);
	int (*set_dontroute)(io_sock_t *sock, int optval);
	int (*get_rcvbuf)(const io_sock_t *sock);
	int (*set_rcvbuf)(io_sock_t *sock, int optval);
	int (*get_sndbuf)(const io_sock_t *sock);
	int (*set_sndbuf)(io_sock_t *sock, int optval);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_sock_get_ctx(const io_sock_t *sock);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_sock_get_exec(const io_sock_t *sock);

/// @see io_dev_cancel()
static inline size_t io_sock_cancel(io_sock_t *sock, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_sock_abort(io_sock_t *sock, struct ev_task *task);

/// Returns a pointer to the abstract I/O device representing the socket.
LELY_IO_SOCK_INLINE io_dev_t *io_sock_get_dev(const io_sock_t *sock);

/**
 * Assigns the specified local network protocol endpoint to a socket as if by
 * POSIX `bind()`. If <b>endp</b> is NULL, an unused local endpoint is used.
 *
 * @param sock      a pointer to a socket.
 * @param endp      a pointer to the endpoint. If not NULL, it is the
 *                  responsibility of the user to ensure the endpoint matches
 *                  the address family and protocol of the socket.
 * @param reuseaddr enables the socket to be bound to an enpoint that is already
 *                  in use by another (perhaps recently closed) socket. This is
 *                  typically achieved by setting the SO_REUSEADDR (on Windows
 *                  and Linux) or SO_REUSEPORT (on Mac OS X and BSD) socket
 *                  options.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SOCK_INLINE int io_sock_bind(
		io_sock_t *sock, const struct io_endp *endp, int reuseaddr);

/**
 * Obtains the local network protocol endpoint to which a socket is bound as if
 * by POSIX `getsockname()`. If the socket has not been bound to a local
 * endpoint, the value at <b>endp</b> is unspecified.
 *
 * @param sock a pointer to a socket.
 * @param endp the address at which to store the endpoint. If not NULL, it is
 *             the responsibility of the user to ensure the endpoint matches the
 *             address family and protocol of the socket.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_bind()
 */
LELY_IO_SOCK_INLINE int io_sock_getsockname(
		const io_sock_t *sock, struct io_endp *endp);

/// Returns 1 if the socket is open and 0 if not.
LELY_IO_SOCK_INLINE int io_sock_is_open(const io_sock_t *sock);

/**
 * Closes the socket if it is open. Any pending socket operations are canceled.
 * Note that this function MAY block if the socket is configured to linger and
 * wait for a gracefull shutdown.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc(). Note that, on POSIX platforms, the socket is
 * closed even when this function reports an error.
 *
 * @post io_sock_is_open() returns 0.
 */
LELY_IO_SOCK_INLINE int io_sock_close(io_sock_t *sock);

/**
 * Polls a socket for I/O events as if by POSIX `poll()`.
 *
 * @param sock    a pointer to a socket.
 * @param events  on input, a pointer to the I/O events to be monitored (any
 *                combination of #IO_EVENT_IN, #IO_EVENT_PRI, #IO_EVENT_OUT,
 *                #IO_EVENT_ERR and #IO_EVENT_HUP). On output, *<b>events</b>
 *                contains the reported events. Note that error and disconnect
 *                events are monitored regardless of whether #IO_EVENT_ERR and
 *                #IO_EVENT_HUP are specified on input.
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SOCK_INLINE int io_sock_wait(io_sock_t *sock, int *events, int timeout);

/**
 * Submits an I/O event wait operation to a socket. The completion task is
 * submitted for execution once an I/O event or an error occurs.
 */
LELY_IO_SOCK_INLINE void io_sock_submit_wait(
		io_sock_t *sock, struct io_sock_wait *wait);

/**
 * Cancels the specified socket I/O event wait operation if it is pending. The
 * completion task is submitted for execution with
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_cancel_wait(
		io_sock_t *sock, struct io_sock_wait *wait);

/**
 * Aborts the specified socket event wait operation if it is pending. If
 * aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_abort_wait(
		io_sock_t *sock, struct io_sock_wait *wait);

/**
 * Submits an asynchronous I/O event wait operation to a socket and creates a
 * future which becomes ready once the wait operation completes (or is
 * canceled). The result of the future is an `int` containing the error number.
 *
 * @param sock   a pointer to a socket.
 * @param exec   a pointer to the executor used to execute the completion
 *               function of the wait operation. If NULL, the default executor
 *               of the socket is used.
 * @param events on input, a pointer to the I/O events to be monitored (any
 *               combination of #IO_EVENT_IN, #IO_EVENT_PRI, #IO_EVENT_OUT,
 *               #IO_EVENT_ERR and #IO_EVENT_HUP). On output, *<b>events</b>
 *               contains the reported events. Note that error and disconnect
 *               events are monitored regardless of whether #IO_EVENT_ERR and
 *               #IO_EVENT_HUP are specified on input.
 * @param pwait  the address at which to store a pointer to the wait operation
 *               (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_async_wait(io_sock_t *sock, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait);

/// Returns and clears the pending error on a socket.
LELY_IO_SOCK_INLINE int io_sock_get_error(io_sock_t *sock);

/**
 * Returns the number of bytes that can be read immediately in a single read
 * operation.
 */
LELY_IO_SOCK_INLINE int io_sock_get_nread(const io_sock_t *sock);

/**
 * Checks whether the standard routing facilities are bypassed for a socket.
 *
 * This option is equivalent to the SO_DONTROUTE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_get_rcvbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_get_dontroute(const io_sock_t *sock);

/**
 * Enables or disables bypassing the standard routing facilities for a socket.
 * If <b>optval</b> is 1, outgoing messages are sent only to destinations on a
 * directly-connected network. This option has the same effect as setting the
 * #IO_MSG_DONTROUTE flag in a send operation.
 *
 * This option is equivalent to the SO_DONTROUTE option at the SOL_SOCKET level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_get_rcvbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_set_dontroute(io_sock_t *sock, int optval);

/**
 * Retrieves the size (in bytes) of the buffer space allocated for receive
 * operations on a socket.
 *
 * This option is equivalent to the SO_RCVBUF option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns the size or the receive buffer, or -1 on error. In the latter case,
 * the error number can be obtained with get_errc().
 *
 * @see io_sock_set_rcvbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_get_rcvbuf(const io_sock_t *sock);

/**
 * Sets the size (in bytes) of the buffer space allocated for receive operations
 * on a socket. On Linux, the kernel doubles this value to allow space for
 * bookkeeping overhead.
 *
 * This option is equivalent to the SO_RCVBUF option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_get_rcvbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_set_rcvbuf(io_sock_t *sock, int optval);

/**
 * Retrieves the size (in bytes) of the buffer space allocated for send
 * operations on a socket.
 *
 * This option is equivalent to the SO_SNDBUF option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns the size or the send buffer, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 *
 * @see io_sock_set_sndbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_get_sndbuf(const io_sock_t *sock);

/**
 * Sets the size (in bytes) of the buffer space allocated for send operations on
 * a socket. On Linux, the kernel doubles this value to allow space for
 * bookkeeping overhead.
 *
 * This option is equivalent to the SO_SNDBUF option at the SOL_SOCKET level on
 * Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_sock_get_sndbuf()
 */
LELY_IO_SOCK_INLINE int io_sock_set_sndbuf(io_sock_t *sock, int optval);

/**
 * Obtains a pointer to a socket I/O event wait operation from a pointer to its
 * completion task.
 */
struct io_sock_wait *io_sock_wait_from_task(struct ev_task *task);

static inline io_ctx_t *
io_sock_get_ctx(const io_sock_t *sock)
{
	return io_dev_get_ctx(io_sock_get_dev(sock));
}

static inline ev_exec_t *
io_sock_get_exec(const io_sock_t *sock)
{
	return io_dev_get_exec(io_sock_get_dev(sock));
}

static inline size_t
io_sock_cancel(io_sock_t *sock, struct ev_task *task)
{
	return io_dev_cancel(io_sock_get_dev(sock), task);
}

static inline size_t
io_sock_abort(io_sock_t *sock, struct ev_task *task)
{
	return io_dev_abort(io_sock_get_dev(sock), task);
}

inline io_dev_t *
io_sock_get_dev(const io_sock_t *sock)
{
	return (*sock)->get_dev(sock);
}

inline int
io_sock_bind(io_sock_t *sock, const struct io_endp *endp, int reuseaddr)
{
	return (*sock)->bind(sock, endp, reuseaddr);
}

inline int
io_sock_getsockname(const io_sock_t *sock, struct io_endp *endp)
{
	return (*sock)->getsockname(sock, endp);
}

inline int
io_sock_is_open(const io_sock_t *sock)
{
	return (*sock)->is_open(sock);
}

inline int
io_sock_close(io_sock_t *sock)
{
	return (*sock)->close(sock);
}

inline int
io_sock_wait(io_sock_t *sock, int *events, int timeout)
{
	return (*sock)->wait(sock, events, timeout);
}

inline void
io_sock_submit_wait(io_sock_t *sock, struct io_sock_wait *wait)
{
	(*sock)->submit_wait(sock, wait);
}

static inline size_t
io_sock_cancel_wait(io_sock_t *sock, struct io_sock_wait *wait)
{
	return io_sock_cancel(sock, &wait->task);
}

static inline size_t
io_sock_abort_wait(io_sock_t *sock, struct io_sock_wait *wait)
{
	return io_sock_abort(sock, &wait->task);
}

inline int
io_sock_get_error(io_sock_t *sock)
{
	return (*sock)->get_error(sock);
}

inline int
io_sock_get_nread(const io_sock_t *sock)
{
	return (*sock)->get_nread(sock);
}

inline int
io_sock_get_dontroute(const io_sock_t *sock)
{
	return (*sock)->get_dontroute(sock);
}

inline int
io_sock_set_dontroute(io_sock_t *sock, int optval)
{
	return (*sock)->set_dontroute(sock, optval);
}

inline int
io_sock_get_rcvbuf(const io_sock_t *sock)
{
	return (*sock)->get_rcvbuf(sock);
}

inline int
io_sock_set_rcvbuf(io_sock_t *sock, int optval)
{
	return (*sock)->set_rcvbuf(sock, optval);
}

inline int
io_sock_get_sndbuf(const io_sock_t *sock)
{
	return (*sock)->get_sndbuf(sock);
}

inline int
io_sock_set_sndbuf(io_sock_t *sock, int optval)
{
	return (*sock)->set_sndbuf(sock, optval);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SOCK_H_
