/**@file
 * This header file is part of the I/O library; it contains the abstract stream
 * socket server interface.
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

#ifndef LELY_IO2_SOCK_STREAM_SRV_H_
#define LELY_IO2_SOCK_STREAM_SRV_H_

#include <lely/io2/sock_stream.h>

#ifndef LELY_IO_SOCK_STREAM_SRV_INLINE
#define LELY_IO_SOCK_STREAM_SRV_INLINE static inline
#endif

/// An abstract stream socket server.
typedef const struct io_sock_stream_srv_vtbl *const io_sock_stream_srv_t;

/**
 * A stream socket server accept operation. The operation is performed as if by
 * POSIX `accept()`.
 */
struct io_sock_stream_srv_accept {
	/**
	 * A pointer to a closed stream socket. On success, <b>sock</b> contains
	 * the accepted socket.
	 */
	io_sock_stream_t *sock;
	/**
	 * The address at which to store the connecting network protocol
	 * endpoint. If not NULL, it is the responsibility of the user to ensure
	 * the endpoint matches the address family and protocol of the socket
	 * and remains valid until the operation completes.
	 */
	struct io_endp *endp;
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
	// The listening socket.
	void *_listen;
	// The accepted socket
	void *_accept;
	// The buffer used by `AcceptEx()` to store the addresses.
	char _buf[2 * (sizeof(struct io_sockaddr_storage) + 16)];
	// The I/O completion packet.
	struct io_cp _cp;
#endif
};

/// The static initializer for #io_sock_stream_srv_accept.
#if _WIN32
#define IO_SOCK_STREAM_SRV_ACCEPT_INIT(sock, endp, exec, func) \
	{ \
		(sock), (endp), EV_TASK_INIT(exec, func), 0, \
				INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, \
				{ 0 }, IO_CP_INIT(NULL) \
	}
#else
#define IO_SOCK_STREAM_SRV_ACCEPT_INIT(sock, endp, exec, func) \
	{ \
		(sock), (endp), EV_TASK_INIT(exec, func), 0 \
	}
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct io_sock_stream_srv_vtbl {
	io_sock_t *(*get_sock)(const io_sock_stream_srv_t *srv);
	int (*get_maxconn)(const io_sock_stream_srv_t *srv);
	int (*listen)(io_sock_stream_srv_t *srv, int backlog);
	int (*is_listening)(const io_sock_stream_srv_t *srv);
	int (*accept)(io_sock_stream_srv_t *srv, io_sock_stream_t *sock,
			struct io_endp *endp, int timeout);
	void (*submit_accept)(io_sock_stream_srv_t *srv,
			struct io_sock_stream_srv_accept *accept);
};

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_sock_stream_srv_get_ctx(
		const io_sock_stream_srv_t *srv);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_sock_stream_srv_get_exec(
		const io_sock_stream_srv_t *srv);

/// @see io_dev_cancel()
static inline size_t io_sock_stream_srv_cancel(
		io_sock_stream_srv_t *srv, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_sock_stream_srv_abort(
		io_sock_stream_srv_t *srv, struct ev_task *task);

/// @see io_sock_get_dev()
static inline io_dev_t *io_sock_stream_srv_get_dev(
		const io_sock_stream_srv_t *srv);

/// @see io_sock_bind()
static inline int io_sock_stream_srv_bind(io_sock_stream_srv_t *srv,
		const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_sock_stream_srv_getsockname(
		const io_sock_stream_srv_t *srv, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_sock_stream_srv_is_open(const io_sock_stream_srv_t *srv);

/// @see io_sock_close()
static inline int io_sock_stream_srv_close(io_sock_stream_srv_t *srv);

/// @see io_sock_wait()
static inline int io_sock_stream_srv_wait(
		io_sock_stream_srv_t *srv, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_sock_stream_srv_submit_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_sock_stream_srv_cancel_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_sock_stream_srv_abort_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_sock_stream_srv_async_wait(
		io_sock_stream_srv_t *srv, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_sock_stream_srv_get_error(io_sock_stream_srv_t *srv);

/**
 * Returns a pointer to the abstract socket representing the stream socket
 * server.
 */
LELY_IO_SOCK_STREAM_SRV_INLINE io_sock_t *io_sock_stream_srv_get_sock(
		const io_sock_stream_srv_t *srv);

/**
 * Returns the maximum number number of pending connections supported by the
 * implementation. On Windos and POSIX platforms, this value equals `SOMAXCONN`.
 *
 * @see io_sock_stream_srv_listen()
 */
LELY_IO_SOCK_STREAM_SRV_INLINE int io_sock_stream_srv_get_maxconn(
		const io_sock_stream_srv_t *srv);

/**
 * Marks a stream socket server as accepting connections as if by
 * POSIX `listen()`. On success, incoming connections can be accepted with
 * io_sock_stream_srv_accept().
 *
 * @param srv     a pointer to an open stream socket server.
 * @param backlog the maximum number of pending connections. If <b>backlog</b>
 *                is 0, an implementation-defined default value is used. The
 *                maximum value for <b>backlog</b> supported by the
 *                implementation can be obtained with
 *                io_sock_stream_srv_get_maxconn().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_stream_srv_is_listening() returns 1.
 */
LELY_IO_SOCK_STREAM_SRV_INLINE int io_sock_stream_srv_listen(
		io_sock_stream_srv_t *srv, int backlog);

/**
 * Returns 1 if the stream socket is accepting connections, 0 if not and -1 on
 * error. In the later case, the error number can be obtained with get_errc().
 * The operation is performed as if by POSIX
 * `getsockopt(..., SOL_SOCKET, SO_ACCEPTCONN, ...)`.
 *
 * @see io_sock_stream_srv_listen()
 */
LELY_IO_SOCK_STREAM_SRV_INLINE int io_sock_stream_srv_is_listening(
		const io_sock_stream_srv_t *srv);

/**
 * Extracts the first pending connection of a stream socket server, opens a
 * connected socket with the same protocol and address family as the server and
 * assigns it to the specified stream socket.
 *
 * @param srv     a pointer to a listening stream socket server.
 * @param sock    a pointer to a closed stream socket. On success, <b>sock</b>
 *                contains the accepted socket.
 * @param endp    the address at which to store the connecting network protocol
 *                endpoint. If not NULL, it is the responsibility of the user to
 *                ensure the endpoint matches the address family and protocol of
 *                the socket.
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 */
LELY_IO_SOCK_STREAM_SRV_INLINE int io_sock_stream_srv_accept(
		io_sock_stream_srv_t *srv, io_sock_stream_t *sock,
		struct io_endp *endp, int timeout);

/**
 * Submits an accept operation to a stream socket server. The completion task
 * is submitted for execution once an incoming connection has been accepted or
 * an error occurs.
 */
LELY_IO_SOCK_STREAM_SRV_INLINE void io_sock_stream_srv_submit_accept(
		io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept);

/**
 * Cancels the specified stream socket server accept operation if it is pending.
 * The completion task is submitted for execution with
 * <b>errc</b> = #errnum2c(#ERRNUM_CANCELED).
 *
 * @returns 1 if the operation was canceled, and 0 if it was not pending.
 *
 * @see io_dev_cancel()
 */
static inline size_t io_sock_stream_srv_cancel_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept);

/**
 * Aborts the specified stream socket server accept operation if it is pending.
 * If aborted, the completion task is _not_ submitted for execution.
 *
 * @returns 1 if the operation was aborted, and 0 if it was not pending.
 *
 * @see io_dev_abort()
 */
static inline size_t io_sock_stream_srv_abort_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept);

/**
 * Submits an asynchronous accept operation to a stream socket server and
 * creates a future which becomes ready once the accept operation completes (or
 * is canceled).  The result of the future is an `int` containing the error
 * number.
 *
 * @param srv     a pointer to a listening stream socket server.
 * @param exec    a pointer to the executor used to execute the completion
 *                function of the connect operation. If NULL, the default
 *                executor of the stream socket is used.
 * @param sock    a pointer to a closed stream socket. On success, <b>sock</b>
 *                contains the accepted socket.
 * @param endp    the address at which to store the connecting network protocol
 *                endpoint. If not NULL, it is the responsibility of the user to
 *                ensure the endpoint matches the address family and protocol of
 *                the socket.
 * @param paccept the address at which to store a pointer to the accept
 *                operation (can be NULL).
 *
 * @returns a pointer to a future, or NULL on error. In the latter case, the
 * error number can be obtained with get_errc().
 */
ev_future_t *io_sock_stream_srv_async_accept(io_sock_stream_srv_t *srv,
		ev_exec_t *exec, io_sock_stream_t *sock, struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept);

/**
 * Obtains a pointer to a stream socket server accept operation from a pointer
 * to its completion task.
 */
struct io_sock_stream_srv_accept *io_sock_stream_srv_accept_from_task(
		struct ev_task *task);

static inline io_ctx_t *
io_sock_stream_srv_get_ctx(const io_sock_stream_srv_t *srv)
{
	return io_dev_get_ctx(io_sock_stream_srv_get_dev(srv));
}

static inline ev_exec_t *
io_sock_stream_srv_get_exec(const io_sock_stream_srv_t *srv)
{
	return io_dev_get_exec(io_sock_stream_srv_get_dev(srv));
}

static inline size_t
io_sock_stream_srv_cancel(io_sock_stream_srv_t *srv, struct ev_task *task)
{
	return io_dev_cancel(io_sock_stream_srv_get_dev(srv), task);
}

static inline size_t
io_sock_stream_srv_abort(io_sock_stream_srv_t *srv, struct ev_task *task)
{
	return io_dev_abort(io_sock_stream_srv_get_dev(srv), task);
}

static inline io_dev_t *
io_sock_stream_srv_get_dev(const io_sock_stream_srv_t *srv)
{
	return io_sock_get_dev(io_sock_stream_srv_get_sock(srv));
}

static inline int
io_sock_stream_srv_bind(io_sock_stream_srv_t *srv, const struct io_endp *endp,
		int reuseaddr)
{
	return io_sock_bind(io_sock_stream_srv_get_sock(srv), endp, reuseaddr);
}

static inline int
io_sock_stream_srv_getsockname(
		const io_sock_stream_srv_t *srv, struct io_endp *endp)
{
	return io_sock_getsockname(io_sock_stream_srv_get_sock(srv), endp);
}

static inline int
io_sock_stream_srv_is_open(const io_sock_stream_srv_t *srv)
{
	return io_sock_is_open(io_sock_stream_srv_get_sock(srv));
}

static inline int
io_sock_stream_srv_close(io_sock_stream_srv_t *srv)
{
	return io_sock_close(io_sock_stream_srv_get_sock(srv));
}

static inline int
io_sock_stream_srv_wait(io_sock_stream_srv_t *srv, int *events, int timeout)
{
	return io_sock_wait(io_sock_stream_srv_get_sock(srv), events, timeout);
}

static inline void
io_sock_stream_srv_submit_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_sock_stream_srv_get_sock(srv), wait);
}

static inline size_t
io_sock_stream_srv_cancel_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_sock_stream_srv_get_sock(srv), wait);
}

static inline size_t
io_sock_stream_srv_abort_wait(
		io_sock_stream_srv_t *srv, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_sock_stream_srv_get_sock(srv), wait);
}

static inline ev_future_t *
io_sock_stream_srv_async_wait(io_sock_stream_srv_t *srv, ev_exec_t *exec,
		int *events, struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_sock_stream_srv_get_sock(srv), exec, events, pwait);
}

static inline int
io_sock_stream_srv_get_error(io_sock_stream_srv_t *srv)
{
	return io_sock_get_error(io_sock_stream_srv_get_sock(srv));
}

inline io_sock_t *
io_sock_stream_srv_get_sock(const io_sock_stream_srv_t *srv)
{
	return (*srv)->get_sock(srv);
}

inline int
io_sock_stream_srv_get_maxconn(const io_sock_stream_srv_t *srv)
{
	return (*srv)->get_maxconn(srv);
}

inline int
io_sock_stream_srv_listen(io_sock_stream_srv_t *srv, int backlog)
{
	return (*srv)->listen(srv, backlog);
}

inline int
io_sock_stream_srv_is_listening(const io_sock_stream_srv_t *srv)
{
	return (*srv)->is_listening(srv);
}

inline int
io_sock_stream_srv_accept(io_sock_stream_srv_t *srv, io_sock_stream_t *sock,
		struct io_endp *endp, int timeout)
{
	return (*srv)->accept(srv, sock, endp, timeout);
}

inline void
io_sock_stream_srv_submit_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept)
{
	(*srv)->submit_accept(srv, accept);
}

static inline size_t
io_sock_stream_srv_cancel_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_cancel(srv, &accept->task);
}

static inline size_t
io_sock_stream_srv_abort_accept(io_sock_stream_srv_t *srv,
		struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_abort(srv, &accept->task);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SOCK_STREAM_SRV_H_
