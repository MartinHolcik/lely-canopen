/**@file
 * This header file is part of the I/O library; it contains the abstract TCP
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

#ifndef LELY_IO2_TCP_H_
#define LELY_IO2_TCP_H_

#include <lely/io2/endp.h>
#include <lely/io2/ipv4.h>
#include <lely/io2/ipv6.h>
#include <lely/io2/sock_stream.h>
#include <lely/io2/sock_stream_srv.h>

#ifndef LELY_IO_TCP_INLINE
#define LELY_IO_TCP_INLINE static inline
#endif

/// The IANA protocol number for TCP.
#define IO_IPPROTO_TCP 6

/// An IPv4 TCP endpoint.
struct io_endp_ipv4_tcp {
	/// &#ipv4
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv4_tcp)`
	int len;
	/// #IO_IPPROTO_TCP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv4 network address.
	struct io_addr_ipv4 ipv4;
};

/**
 * The static initializer for #io_endp_ipv4_tcp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV4_TCP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv4, \
				sizeof(struct io_endp_ipv4_tcp), \
				IO_IPPROTO_TCP, 0, IO_ADDR_IPV4_INIT \
	}

union io_endp_ipv4_tcp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv4_tcp _ipv4_tcp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv4 TCP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV4_TCP_STRLEN (IO_ADDR_IPV4_STRLEN + 6)

/// An IPv6 TCP endpoint.
struct io_endp_ipv6_tcp {
	/// &#ipv6
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv6_tcp)`
	int len;
	/// #IO_IPPROTO_TCP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv6 network address.
	struct io_addr_ipv6 ipv6;
};

/**
 * The static initializer for #io_endp_ipv6_tcp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV6_TCP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv6, \
				sizeof(struct io_endp_ipv6_tcp), \
				IO_IPPROTO_TCP, 0, IO_ADDR_IPV6_INIT \
	}

union io_endp_ipv6_tcp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv6_tcp _ipv6_tcp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv6 TCP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV6_TCP_STRLEN (IO_ADDR_IPV6_STRLEN + 8)

/// An abstract TCP server.
typedef const struct io_tcp_srv_vtbl *const io_tcp_srv_t;

/// An abstract TCP socket.
typedef const struct io_tcp_vtbl *const io_tcp_t;

#ifdef __cplusplus
extern "C" {
#endif

struct io_tcp_srv_vtbl {
	io_sock_stream_srv_t *(*get_sock_stream_srv)(const io_tcp_srv_t *tcp);
	int (*open_ipv4)(io_tcp_srv_t *tcp);
	int (*open_ipv6)(io_tcp_srv_t *tcp, int v6only);
};

struct io_tcp_vtbl {
	io_sock_stream_t *(*get_sock_stream)(const io_tcp_t *tcp);
	int (*open_ipv4)(io_tcp_t *tcp);
	int (*open_ipv6)(io_tcp_t *tcp, int v6only);
	int (*get_nodelay)(const io_tcp_t *tcp);
	int (*set_nodelay)(io_tcp_t *tcp, int optval);
};

/**
 * Creates an IPv4 TCP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv4_tcp_to_string()
 */
int io_endp_ipv4_tcp_set_from_string(
		struct io_endp_ipv4_tcp *endp, const char *str);

/**
 * Stores a text representation of the IPv4 TCP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV4_TCP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv4_tcp_to_string()
 */
void io_endp_ipv4_tcp_to_string(const struct io_endp_ipv4_tcp *endp, char *str);

/**
 * Creates an IPv6 TCP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv6_tcp_to_string()
 */
int io_endp_ipv6_tcp_set_from_string(
		struct io_endp_ipv6_tcp *endp, const char *str);

/**
 * Stores a text representation of the IPv6 TCP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV6_TCP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv6_tcp_to_string()
 */
void io_endp_ipv6_tcp_to_string(const struct io_endp_ipv6_tcp *endp, char *str);

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_tcp_srv_get_ctx(const io_tcp_srv_t *tcp);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_tcp_srv_get_exec(const io_tcp_srv_t *tcp);

/// @see io_dev_cancel()
static inline size_t io_tcp_srv_cancel(io_tcp_srv_t *tcp, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_tcp_srv_abort(io_tcp_srv_t *tcp, struct ev_task *task);

/// @see io_sock_bind()
static inline int io_tcp_srv_bind(
		io_tcp_srv_t *tcp, const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_tcp_srv_getsockname(
		const io_tcp_srv_t *tcp, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_tcp_srv_is_open(const io_tcp_srv_t *tcp);

/// @see io_sock_close()
static inline int io_tcp_srv_close(io_tcp_srv_t *tcp);

/// @see io_sock_wait()
static inline int io_tcp_srv_wait(io_tcp_srv_t *tcp, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_tcp_srv_submit_wait(
		io_tcp_srv_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_tcp_srv_cancel_wait(
		io_tcp_srv_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_tcp_srv_abort_wait(
		io_tcp_srv_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_tcp_srv_async_wait(io_tcp_srv_t *tcp,
		ev_exec_t *exec, int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_tcp_srv_get_error(io_tcp_srv_t *tcp);

/// @see io_sock_stream_srv_get_maxconn()
static inline int io_tcp_srv_get_maxconn(const io_tcp_srv_t *tcp);

/// @see io_sock_stream_srv_listen()
static inline int io_tcp_srv_listen(io_tcp_srv_t *tcp, int backlog);

/// @see io_sock_stream_srv_is_listening()
static inline int io_tcp_srv_is_listening(const io_tcp_srv_t *tcp);

/// @see io_sock_stream_srv_accept()
static inline int io_tcp_srv_accept(io_tcp_srv_t *tcp, io_tcp_t *sock,
		struct io_endp *endp, int timeout);

/// @see io_sock_stream_srv_submit_accept()
static inline void io_tcp_srv_submit_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_cancel_accept()
static inline size_t io_tcp_srv_cancel_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_abort_accept()
static inline size_t io_tcp_srv_abort_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept);

/// @see io_sock_stream_srv_async_accept()
static inline ev_future_t *io_tcp_srv_async_accept(io_tcp_srv_t *tcp,
		ev_exec_t *exec, io_tcp_t *sock, struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept);

/// Returns a pointer to the abstract I/O device representing the TCP server.
static inline io_dev_t *io_tcp_srv_get_dev(const io_tcp_srv_t *tcp);

/// Returns a pointer to the abstract socket representing the TCP server.
static inline io_sock_t *io_tcp_srv_get_sock(const io_tcp_srv_t *tcp);

/// Returns a pointer to the abstract stream socket representing the TCP server.
LELY_IO_TCP_INLINE io_sock_stream_srv_t *io_tcp_srv_get_sock_stream_srv(
		const io_tcp_srv_t *tcp);

/**
 * Opens a socket that can be used to accept incoming IPv4 TCP connections as if
 * by POSIX `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_TCP_INLINE int io_tcp_srv_open_ipv4(io_tcp_srv_t *tcp);

/**
 * Opens a socket that can be used to accept incoming IPv6 TCP connections as if
 * by POSIX `socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)`. If <b>v6only</b> is
 * on-zero, and the implementation supports dual stack, the resulting socket can
 * also be used to accept incoming IPv4-mapped TCP connections.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_TCP_INLINE int io_tcp_srv_open_ipv6(io_tcp_srv_t *tcp, int v6only);

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_tcp_get_ctx(const io_tcp_t *tcp);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_tcp_get_exec(const io_tcp_t *tcp);

/// @see io_dev_cancel()
static inline size_t io_tcp_cancel(io_tcp_t *tcp, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_tcp_abort(io_tcp_t *tcp, struct ev_task *task);

/// @see io_sock_bind()
static inline int io_tcp_bind(
		io_tcp_t *tcp, const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_tcp_getsockname(const io_tcp_t *tcp, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_tcp_is_open(const io_tcp_t *tcp);

/// @see io_sock_close()
static inline int io_tcp_close(io_tcp_t *tcp);

/// @see io_sock_wait()
static inline int io_tcp_wait(io_tcp_t *tcp, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_tcp_submit_wait(io_tcp_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_tcp_cancel_wait(
		io_tcp_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_tcp_abort_wait(
		io_tcp_t *tcp, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_tcp_async_wait(io_tcp_t *tcp, ev_exec_t *exec,
		int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_tcp_get_error(io_tcp_t *tcp);

/// @see io_sock_get_nread()
static inline int io_tcp_get_nread(const io_tcp_t *tcp);

/// @see io_sock_get_dontroute()
static inline int io_tcp_get_dontroute(const io_tcp_t *tcp);

/// @see io_sock_set_dontroute()
static inline int io_tcp_set_dontroute(io_tcp_t *tcp, int optval);

/// @see io_sock_get_rcvbuf()
static inline int io_tcp_get_rcvbuf(const io_tcp_t *tcp);

/// @see io_sock_set_rcvbuf()
static inline int io_tcp_set_rcvbuf(io_tcp_t *tcp, int optval);

/// @see io_sock_get_sndbuf()
static inline int io_tcp_get_sndbuf(const io_tcp_t *tcp);

/// @see io_sock_set_sndbuf()
static inline int io_tcp_set_sndbuf(io_tcp_t *tcp, int optval);

/// @see io_stream_readv()
static inline ssize_t io_tcp_readv(
		io_tcp_t *tcp, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_readv()
static inline void io_tcp_submit_readv(
		io_tcp_t *tcp, struct io_stream_readv *readv);

/// @see io_stream_cancel_readv()
static inline size_t io_tcp_cancel_readv(
		io_tcp_t *tcp, struct io_stream_readv *readv);

/// @see io_stream_abort_readv()
static inline size_t io_tcp_abort_readv(
		io_tcp_t *tcp, struct io_stream_readv *readv);

/// @see io_stream_async_readv()
static inline ev_future_t *io_tcp_async_readv(io_tcp_t *tcp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv);

/// @see io_stream_read()
static inline ssize_t io_tcp_read(io_tcp_t *tcp, void *buf, size_t nbytes);

/// @see io_stream_submit_read()
static inline void io_tcp_submit_read(
		io_tcp_t *tcp, struct io_stream_read *read);

/// @see io_stream_cancel_read()
static inline size_t io_tcp_cancel_read(
		io_tcp_t *tcp, struct io_stream_read *read);

/// @see io_stream_abort_read()
static inline size_t io_tcp_abort_read(
		io_tcp_t *tcp, struct io_stream_read *read);

/// @see io_stream_async_read()
static inline ev_future_t *io_tcp_async_read(io_tcp_t *tcp, ev_exec_t *exec,
		void *buf, size_t nbytes, struct io_stream_read **pread);

/// @see io_stream_writev()
static inline ssize_t io_tcp_writev(
		io_tcp_t *tcp, const struct io_buf *buf, int bufcnt);

/// @see io_stream_submit_writev()
static inline void io_tcp_submit_writev(
		io_tcp_t *tcp, struct io_stream_writev *writev);

/// @see io_stream_cancel_writev()
static inline size_t io_tcp_cancel_writev(
		io_tcp_t *tcp, struct io_stream_writev *writev);

/// @see io_stream_abort_writev()
static inline size_t io_tcp_abort_writev(
		io_tcp_t *tcp, struct io_stream_writev *writev);

/// @see io_stream_async_writev()
static inline ev_future_t *io_tcp_async_writev(io_tcp_t *tcp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev);

/// @see io_stream_write()
static inline ssize_t io_tcp_write(
		io_tcp_t *tcp, const void *buf, size_t nbytes);

/// @see io_stream_submit_write()
static inline void io_tcp_submit_write(
		io_tcp_t *tcp, struct io_stream_write *write);

/// @see io_stream_cancel_write()
static inline size_t io_tcp_cancel_write(
		io_tcp_t *tcp, struct io_stream_write *write);

/// @see io_stream_abort_write()
static inline size_t io_tcp_abort_write(
		io_tcp_t *tcp, struct io_stream_write *write);

/// @see io_sock_stream_connect()
static inline int io_tcp_connect(io_tcp_t *tcp, const struct io_endp *endp);

/// @see io_sock_stream_submit_connect()
static inline void io_tcp_submit_connect(
		io_tcp_t *tcp, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_cancel_connect()
static inline size_t io_tcp_cancel_connect(
		io_tcp_t *tcp, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_abort_connect()
static inline size_t io_tcp_abort_connect(
		io_tcp_t *tcp, struct io_sock_stream_connect *connect);

/// @see io_sock_stream_async_connect()
static inline ev_future_t *io_tcp_async_connect(io_tcp_t *tcp, ev_exec_t *exec,
		const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect);

/// @see io_sock_stream_getpeername()
static inline int io_tcp_getpeername(const io_tcp_t *tcp, struct io_endp *endp);

/// @see io_sock_stream_recvmsg()
static inline ssize_t io_tcp_recvmsg(io_tcp_t *tcp, const struct io_buf *buf,
		int bufcnt, int *flags, int timeout);

/// @see io_sock_stream_submit_recvmsg()
static inline void io_tcp_submit_recvmsg(
		io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_cancel_recvmsg()
static inline size_t io_tcp_cancel_recvmsg(
		io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_abort_recvmsg()
static inline size_t io_tcp_abort_recvmsg(
		io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg);

/// @see io_sock_stream_async_recvmsg()
static inline ev_future_t *io_tcp_async_recvmsg(io_tcp_t *tcp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_sock_stream_recvmsg **precvmsg);

/// @see io_sock_stream_recv()
static inline ssize_t io_tcp_recv(io_tcp_t *tcp, void *buf, size_t nbytes,
		int *flags, int timeout);

/// @see io_sock_stream_submit_recv()
static inline void io_tcp_submit_recv(
		io_tcp_t *tcp, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_cancel_recv()
static inline size_t io_tcp_cancel_recv(
		io_tcp_t *tcp, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_abort_recv()
static inline size_t io_tcp_abort_recv(
		io_tcp_t *tcp, struct io_sock_stream_recv *recv);

/// @see io_sock_stream_async_recv()
static inline ev_future_t *io_tcp_async_recv(io_tcp_t *tcp, ev_exec_t *exec,
		void *buf, size_t nbytes, int *flags,
		struct io_sock_stream_recv **precv);

/// @see io_sock_stream_sendmsg()
static inline ssize_t io_tcp_sendmsg(io_tcp_t *tcp, const struct io_buf *buf,
		int bufcnt, int flags, int timeout);

/// @see io_sock_stream_submit_sendmsg()
static inline void io_tcp_submit_sendmsg(
		io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_cancel_sendmsg()
static inline size_t io_tcp_cancel_sendmsg(
		io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_abort_sendmsg()
static inline size_t io_tcp_abort_sendmsg(
		io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg);

/// @see io_sock_stream_async_sendmsg()
static inline ev_future_t *io_tcp_async_sendmsg(io_tcp_t *tcp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		struct io_sock_stream_sendmsg **psendmsg);

/// @see io_sock_stream_send()
static inline ssize_t io_tcp_send(io_tcp_t *tcp, const void *buf, size_t nbytes,
		int flags, int timeout);

/// @see io_sock_stream_submit_send()
static inline void io_tcp_submit_send(
		io_tcp_t *tcp, struct io_sock_stream_send *send);

/// @see io_sock_stream_cancel_send()
static inline size_t io_tcp_cancel_send(
		io_tcp_t *tcp, struct io_sock_stream_send *send);

/// @see io_sock_stream_abort_send()
static inline size_t io_tcp_abort_send(
		io_tcp_t *tcp, struct io_sock_stream_send *send);

/// @see io_sock_stream_async_send()
static inline ev_future_t *io_tcp_async_send(io_tcp_t *tcp, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		struct io_sock_stream_send **psend);

/// @see io_sock_stream_shutdown()
static inline int io_tcp_shutdown(io_tcp_t *tcp, int how);

/// @see io_sock_stream_get_keepalive()
static inline int io_tcp_get_keepalive(const io_tcp_t *tcp);

/// @see io_sock_stream_set_keepalive()
static inline int io_tcp_set_keepalive(io_tcp_t *tcp, int optval);

/// @see io_sock_stream_get_linger()
static inline int io_tcp_get_linger(
		const io_tcp_t *tcp, int *ponoff, int *plinger);

/// @see io_sock_stream_set_linger()
static inline int io_tcp_set_linger(io_tcp_t *tcp, int onoff, int linger);

/// @see io_sock_stream_get_oobinline()
static inline int io_tcp_get_oobinline(const io_tcp_t *tcp);

/// @see io_sock_stream_set_oobinline()
static inline int io_tcp_set_oobinline(io_tcp_t *tcp, int optval);

/// @see io_sock_stream_atmark()
static inline int io_tcp_atmark(const io_tcp_t *tcp);

/// Returns a pointer to the abstract I/O device representing the TCP socket.
static inline io_dev_t *io_tcp_get_dev(const io_tcp_t *tcp);

/// Returns a pointer to the abstract socket representing the TCP socket.
static inline io_sock_t *io_tcp_get_sock(const io_tcp_t *tcp);

/// Returns a pointer to the abstract stream representing the TCP socket.
static inline io_stream_t *io_tcp_get_stream(const io_tcp_t *tcp);

/// Returns a pointer to the abstract stream socket representing the TCP socket.
LELY_IO_TCP_INLINE io_sock_stream_t *io_tcp_get_sock_stream(
		const io_tcp_t *tcp);

/**
 * Opens a socket that can be used to connect to an IPv4 TCP server as if by
 * POSIX `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_TCP_INLINE int io_tcp_open_ipv4(io_tcp_t *tcp);

/**
 * Opens a socket that can be used to connect to an IPv6 TCP server as if by
 * POSIX `socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)`. If <b>v6only</b> is
 * on-zero, and the implementation supports dual stack, the resulting socket can
 * also be used to connect to an IPv4-mapped TCP server.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_TCP_INLINE int io_tcp_open_ipv6(io_tcp_t *tcp, int v6only);

/**
 * Checks whether Nagle's algorithm is enabled or disabled for the TCP socket.
 *
 * This option is equivalent to the TCP_NODELAY option at the IPPROTO_TCP level
 * on Windows and POSIX platforms.
 *
 * @returns 1 if the algorithm is _disabled_, 0 if not and -1 on error. In the
 * latter case, the error number can be obtained with get_errc().
 *
 * @see io_tcp_set_nodelay()
 */
LELY_IO_TCP_INLINE int io_tcp_get_nodelay(const io_tcp_t *tcp);

/**
 * Enables or disables Nagle's algorithm (see
 * <a href="https://tools.ietf.org/html/rfc896">RFC 896</a>) for the TCP socket.
 * When <b>optval</b> is 1, the algorithm is _disabled_ and the implementation
 * will avoid coalescing of small segments.
 *
 * This option is equivalent to the TCP_NODELAY option at the IPPROTO_TCP level
 * on Windows and POSIX platforms.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_tcp_get_nodelay()
 */
LELY_IO_TCP_INLINE int io_tcp_set_nodelay(io_tcp_t *tcp, int optval);

static inline io_ctx_t *
io_tcp_srv_get_ctx(const io_tcp_srv_t *tcp)
{
	return io_dev_get_ctx(io_tcp_srv_get_dev(tcp));
}

static inline ev_exec_t *
io_tcp_srv_get_exec(const io_tcp_srv_t *tcp)
{
	return io_dev_get_exec(io_tcp_srv_get_dev(tcp));
}

static inline size_t
io_tcp_srv_cancel(io_tcp_srv_t *tcp, struct ev_task *task)
{
	return io_dev_cancel(io_tcp_srv_get_dev(tcp), task);
}

static inline size_t
io_tcp_srv_abort(io_tcp_srv_t *tcp, struct ev_task *task)
{
	return io_dev_abort(io_tcp_srv_get_dev(tcp), task);
}

static inline int
io_tcp_srv_bind(io_tcp_srv_t *tcp, const struct io_endp *endp, int reuseaddr)
{
	return io_sock_bind(io_tcp_srv_get_sock(tcp), endp, reuseaddr);
}

static inline int
io_tcp_srv_getsockname(const io_tcp_srv_t *tcp, struct io_endp *endp)
{
	return io_sock_getsockname(io_tcp_srv_get_sock(tcp), endp);
}

static inline int
io_tcp_srv_is_open(const io_tcp_srv_t *tcp)
{
	return io_sock_is_open(io_tcp_srv_get_sock(tcp));
}

static inline int
io_tcp_srv_close(io_tcp_srv_t *tcp)
{
	return io_sock_close(io_tcp_srv_get_sock(tcp));
}

static inline int
io_tcp_srv_wait(io_tcp_srv_t *tcp, int *events, int timeout)
{
	return io_sock_wait(io_tcp_srv_get_sock(tcp), events, timeout);
}

static inline void
io_tcp_srv_submit_wait(io_tcp_srv_t *tcp, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_tcp_srv_get_sock(tcp), wait);
}

static inline size_t
io_tcp_srv_cancel_wait(io_tcp_srv_t *tcp, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_tcp_srv_get_sock(tcp), wait);
}

static inline size_t
io_tcp_srv_abort_wait(io_tcp_srv_t *tcp, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_tcp_srv_get_sock(tcp), wait);
}

static inline ev_future_t *
io_tcp_srv_async_wait(io_tcp_srv_t *tcp, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(
			io_tcp_srv_get_sock(tcp), exec, events, pwait);
}

static inline int
io_tcp_srv_get_error(io_tcp_srv_t *tcp)
{
	return io_sock_get_error(io_tcp_srv_get_sock(tcp));
}

static inline int
io_tcp_srv_get_maxconn(const io_tcp_srv_t *tcp)
{
	return io_sock_stream_srv_get_maxconn(
			io_tcp_srv_get_sock_stream_srv(tcp));
}

static inline int
io_tcp_srv_listen(io_tcp_srv_t *tcp, int backlog)
{
	return io_sock_stream_srv_listen(
			io_tcp_srv_get_sock_stream_srv(tcp), backlog);
}

static inline int
io_tcp_srv_is_listening(const io_tcp_srv_t *tcp)
{
	return io_sock_stream_srv_is_listening(
			io_tcp_srv_get_sock_stream_srv(tcp));
}

static inline int
io_tcp_srv_accept(io_tcp_srv_t *tcp, io_tcp_t *sock, struct io_endp *endp,
		int timeout)
{
	return io_sock_stream_srv_accept(io_tcp_srv_get_sock_stream_srv(tcp),
			io_tcp_get_sock_stream(sock), endp, timeout);
}

static inline void
io_tcp_srv_submit_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept)
{
	io_sock_stream_srv_submit_accept(
			io_tcp_srv_get_sock_stream_srv(tcp), accept);
}

static inline size_t
io_tcp_srv_cancel_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_cancel_accept(
			io_tcp_srv_get_sock_stream_srv(tcp), accept);
}

static inline size_t
io_tcp_srv_abort_accept(
		io_tcp_srv_t *tcp, struct io_sock_stream_srv_accept *accept)
{
	return io_sock_stream_srv_abort_accept(
			io_tcp_srv_get_sock_stream_srv(tcp), accept);
}

static inline ev_future_t *
io_tcp_srv_async_accept(io_tcp_srv_t *tcp, ev_exec_t *exec, io_tcp_t *sock,
		struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept)
{
	return io_sock_stream_srv_async_accept(
			io_tcp_srv_get_sock_stream_srv(tcp), exec,
			io_tcp_get_sock_stream(sock), endp, paccept);
}

static inline io_dev_t *
io_tcp_srv_get_dev(const io_tcp_srv_t *tcp)
{
	return io_sock_stream_srv_get_dev(io_tcp_srv_get_sock_stream_srv(tcp));
}

static inline io_sock_t *
io_tcp_srv_get_sock(const io_tcp_srv_t *tcp)
{
	return io_sock_stream_srv_get_sock(io_tcp_srv_get_sock_stream_srv(tcp));
}

inline io_sock_stream_srv_t *
io_tcp_srv_get_sock_stream_srv(const io_tcp_srv_t *tcp)
{
	return (*tcp)->get_sock_stream_srv(tcp);
}

inline int
io_tcp_srv_open_ipv4(io_tcp_srv_t *tcp)
{
	return (*tcp)->open_ipv4(tcp);
}

inline int
io_tcp_srv_open_ipv6(io_tcp_srv_t *tcp, int v6only)
{
	return (*tcp)->open_ipv6(tcp, v6only);
}

static inline io_ctx_t *
io_tcp_get_ctx(const io_tcp_t *tcp)
{
	return io_dev_get_ctx(io_tcp_get_dev(tcp));
}

static inline ev_exec_t *
io_tcp_get_exec(const io_tcp_t *tcp)
{
	return io_dev_get_exec(io_tcp_get_dev(tcp));
}

static inline size_t
io_tcp_cancel(io_tcp_t *tcp, struct ev_task *task)
{
	return io_dev_cancel(io_tcp_get_dev(tcp), task);
}

static inline size_t
io_tcp_abort(io_tcp_t *tcp, struct ev_task *task)
{
	return io_dev_abort(io_tcp_get_dev(tcp), task);
}

static inline int
io_tcp_bind(io_tcp_t *tcp, const struct io_endp *endp, int reuseaddr)
{
	return io_sock_bind(io_tcp_get_sock(tcp), endp, reuseaddr);
}

static inline int
io_tcp_getsockname(const io_tcp_t *tcp, struct io_endp *endp)
{
	return io_sock_getsockname(io_tcp_get_sock(tcp), endp);
}

static inline int
io_tcp_is_open(const io_tcp_t *tcp)
{
	return io_sock_is_open(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_wait(io_tcp_t *tcp, int *events, int timeout)
{
	return io_sock_wait(io_tcp_get_sock(tcp), events, timeout);
}

static inline void
io_tcp_submit_wait(io_tcp_t *tcp, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_tcp_get_sock(tcp), wait);
}

static inline size_t
io_tcp_cancel_wait(io_tcp_t *tcp, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_tcp_get_sock(tcp), wait);
}

static inline size_t
io_tcp_abort_wait(io_tcp_t *tcp, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_tcp_get_sock(tcp), wait);
}

static inline ev_future_t *
io_tcp_async_wait(io_tcp_t *tcp, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(io_tcp_get_sock(tcp), exec, events, pwait);
}

static inline int
io_tcp_close(io_tcp_t *tcp)
{
	return io_sock_close(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_get_error(io_tcp_t *tcp)
{
	return io_sock_get_error(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_get_nread(const io_tcp_t *tcp)
{
	return io_sock_get_nread(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_get_dontroute(const io_tcp_t *tcp)
{
	return io_sock_get_dontroute(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_set_dontroute(io_tcp_t *tcp, int optval)
{
	return io_sock_set_dontroute(io_tcp_get_sock(tcp), optval);
}

static inline int
io_tcp_get_rcvbuf(const io_tcp_t *tcp)
{
	return io_sock_get_rcvbuf(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_set_rcvbuf(io_tcp_t *tcp, int optval)
{
	return io_sock_set_rcvbuf(io_tcp_get_sock(tcp), optval);
}

static inline int
io_tcp_get_sndbuf(const io_tcp_t *tcp)
{
	return io_sock_get_sndbuf(io_tcp_get_sock(tcp));
}

static inline int
io_tcp_set_sndbuf(io_tcp_t *tcp, int optval)
{
	return io_sock_set_sndbuf(io_tcp_get_sock(tcp), optval);
}

static inline ssize_t
io_tcp_readv(io_tcp_t *tcp, const struct io_buf *buf, int bufcnt)
{
	return io_stream_readv(io_tcp_get_stream(tcp), buf, bufcnt);
}

static inline void
io_tcp_submit_readv(io_tcp_t *tcp, struct io_stream_readv *readv)
{
	io_stream_submit_readv(io_tcp_get_stream(tcp), readv);
}

static inline size_t
io_tcp_cancel_readv(io_tcp_t *tcp, struct io_stream_readv *readv)
{
	return io_stream_cancel_readv(io_tcp_get_stream(tcp), readv);
}

static inline size_t
io_tcp_abort_readv(io_tcp_t *tcp, struct io_stream_readv *readv)
{
	return io_stream_abort_readv(io_tcp_get_stream(tcp), readv);
}

static inline ev_future_t *
io_tcp_async_readv(io_tcp_t *tcp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, struct io_stream_readv **preadv)
{
	return io_stream_async_readv(
			io_tcp_get_stream(tcp), exec, buf, bufcnt, preadv);
}

static inline ssize_t
io_tcp_read(io_tcp_t *tcp, void *buf, size_t nbytes)
{
	return io_stream_read(io_tcp_get_stream(tcp), buf, nbytes);
}

static inline void
io_tcp_submit_read(io_tcp_t *tcp, struct io_stream_read *read)
{
	io_stream_submit_read(io_tcp_get_stream(tcp), read);
}

static inline size_t
io_tcp_cancel_read(io_tcp_t *tcp, struct io_stream_read *read)
{
	return io_stream_cancel_read(io_tcp_get_stream(tcp), read);
}

static inline size_t
io_tcp_abort_read(io_tcp_t *tcp, struct io_stream_read *read)
{
	return io_stream_abort_read(io_tcp_get_stream(tcp), read);
}

static inline ev_future_t *
io_tcp_async_read(io_tcp_t *tcp, ev_exec_t *exec, void *buf, size_t nbytes,
		struct io_stream_read **pread)
{
	return io_stream_async_read(
			io_tcp_get_stream(tcp), exec, buf, nbytes, pread);
}

static inline ssize_t
io_tcp_writev(io_tcp_t *tcp, const struct io_buf *buf, int bufcnt)
{
	return io_stream_writev(io_tcp_get_stream(tcp), buf, bufcnt);
}

static inline void
io_tcp_submit_writev(io_tcp_t *tcp, struct io_stream_writev *writev)
{
	io_stream_submit_writev(io_tcp_get_stream(tcp), writev);
}

static inline size_t
io_tcp_cancel_writev(io_tcp_t *tcp, struct io_stream_writev *writev)
{
	return io_stream_cancel_writev(io_tcp_get_stream(tcp), writev);
}

static inline size_t
io_tcp_abort_writev(io_tcp_t *tcp, struct io_stream_writev *writev)
{
	return io_stream_abort_writev(io_tcp_get_stream(tcp), writev);
}

static inline ev_future_t *
io_tcp_async_writev(io_tcp_t *tcp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, struct io_stream_writev **pwritev)
{
	return io_stream_async_writev(
			io_tcp_get_stream(tcp), exec, buf, bufcnt, pwritev);
}

static inline ssize_t
io_tcp_write(io_tcp_t *tcp, const void *buf, size_t nbytes)
{
	return io_stream_write(io_tcp_get_stream(tcp), buf, nbytes);
}

static inline void
io_tcp_submit_write(io_tcp_t *tcp, struct io_stream_write *write)
{
	io_stream_submit_write(io_tcp_get_stream(tcp), write);
}

static inline size_t
io_tcp_cancel_write(io_tcp_t *tcp, struct io_stream_write *write)
{
	return io_stream_cancel_write(io_tcp_get_stream(tcp), write);
}

static inline size_t
io_tcp_abort_write(io_tcp_t *tcp, struct io_stream_write *write)
{
	return io_stream_abort_write(io_tcp_get_stream(tcp), write);
}

static inline ev_future_t *
io_tcp_async_write(io_tcp_t *tcp, ev_exec_t *exec, const void *buf,
		size_t nbytes, struct io_stream_write **pwrite)
{
	return io_stream_async_write(
			io_tcp_get_stream(tcp), exec, buf, nbytes, pwrite);
}

static inline int
io_tcp_connect(io_tcp_t *tcp, const struct io_endp *endp)
{
	return io_sock_stream_connect(io_tcp_get_sock_stream(tcp), endp);
}

static inline void
io_tcp_submit_connect(io_tcp_t *tcp, struct io_sock_stream_connect *connect)
{
	io_sock_stream_submit_connect(io_tcp_get_sock_stream(tcp), connect);
}

static inline size_t
io_tcp_cancel_connect(io_tcp_t *tcp, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_cancel_connect(
			io_tcp_get_sock_stream(tcp), connect);
}

static inline size_t
io_tcp_abort_connect(io_tcp_t *tcp, struct io_sock_stream_connect *connect)
{
	return io_sock_stream_abort_connect(
			io_tcp_get_sock_stream(tcp), connect);
}

static inline ev_future_t *
io_tcp_async_connect(io_tcp_t *tcp, ev_exec_t *exec, const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect)
{
	return io_sock_stream_async_connect(
			io_tcp_get_sock_stream(tcp), exec, endp, pconnect);
}

static inline int
io_tcp_getpeername(const io_tcp_t *tcp, struct io_endp *endp)
{
	return io_sock_stream_getpeername(io_tcp_get_sock_stream(tcp), endp);
}

static inline ssize_t
io_tcp_recvmsg(io_tcp_t *tcp, const struct io_buf *buf, int bufcnt, int *flags,
		int timeout)
{
	return io_sock_stream_recvmsg(io_tcp_get_sock_stream(tcp), buf, bufcnt,
			flags, timeout);
}

static inline void
io_tcp_submit_recvmsg(io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg)
{
	io_sock_stream_submit_recvmsg(io_tcp_get_sock_stream(tcp), recvmsg);
}

static inline size_t
io_tcp_cancel_recvmsg(io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_cancel_recvmsg(
			io_tcp_get_sock_stream(tcp), recvmsg);
}

static inline size_t
io_tcp_abort_recvmsg(io_tcp_t *tcp, struct io_sock_stream_recvmsg *recvmsg)
{
	return io_sock_stream_abort_recvmsg(
			io_tcp_get_sock_stream(tcp), recvmsg);
}

static inline ev_future_t *
io_tcp_async_recvmsg(io_tcp_t *tcp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, int *flags,
		struct io_sock_stream_recvmsg **precvmsg)
{
	return io_sock_stream_async_recvmsg(io_tcp_get_sock_stream(tcp), exec,
			buf, bufcnt, flags, precvmsg);
}

static inline ssize_t
io_tcp_recv(io_tcp_t *tcp, void *buf, size_t nbytes, int *flags, int timeout)
{
	return io_sock_stream_recv(io_tcp_get_sock_stream(tcp), buf, nbytes,
			flags, timeout);
}

static inline void
io_tcp_submit_recv(io_tcp_t *tcp, struct io_sock_stream_recv *recv)
{
	io_sock_stream_submit_recv(io_tcp_get_sock_stream(tcp), recv);
}

static inline size_t
io_tcp_cancel_recv(io_tcp_t *tcp, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_cancel_recv(io_tcp_get_sock_stream(tcp), recv);
}

static inline size_t
io_tcp_abort_recv(io_tcp_t *tcp, struct io_sock_stream_recv *recv)
{
	return io_sock_stream_abort_recv(io_tcp_get_sock_stream(tcp), recv);
}

static inline ev_future_t *
io_tcp_async_recv(io_tcp_t *tcp, ev_exec_t *exec, void *buf, size_t nbytes,
		int *flags, struct io_sock_stream_recv **precv)
{
	return io_sock_stream_async_recv(io_tcp_get_sock_stream(tcp), exec, buf,
			nbytes, flags, precv);
}

static inline ssize_t
io_tcp_sendmsg(io_tcp_t *tcp, const struct io_buf *buf, int bufcnt, int flags,
		int timeout)
{
	return io_sock_stream_sendmsg(io_tcp_get_sock_stream(tcp), buf, bufcnt,
			flags, timeout);
}

static inline void
io_tcp_submit_sendmsg(io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg)
{
	io_sock_stream_submit_sendmsg(io_tcp_get_sock_stream(tcp), sendmsg);
}

static inline size_t
io_tcp_cancel_sendmsg(io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_cancel_sendmsg(
			io_tcp_get_sock_stream(tcp), sendmsg);
}

static inline size_t
io_tcp_abort_sendmsg(io_tcp_t *tcp, struct io_sock_stream_sendmsg *sendmsg)
{
	return io_sock_stream_abort_sendmsg(
			io_tcp_get_sock_stream(tcp), sendmsg);
}

static inline ev_future_t *
io_tcp_async_sendmsg(io_tcp_t *tcp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, int flags, struct io_sock_stream_sendmsg **psendmsg)
{
	return io_sock_stream_async_sendmsg(io_tcp_get_sock_stream(tcp), exec,
			buf, bufcnt, flags, psendmsg);
}

static inline ssize_t
io_tcp_send(io_tcp_t *tcp, const void *buf, size_t nbytes, int flags,
		int timeout)
{
	return io_sock_stream_send(io_tcp_get_sock_stream(tcp), buf, nbytes,
			flags, timeout);
}

static inline void
io_tcp_submit_send(io_tcp_t *tcp, struct io_sock_stream_send *send)
{
	io_sock_stream_submit_send(io_tcp_get_sock_stream(tcp), send);
}

static inline size_t
io_tcp_cancel_send(io_tcp_t *tcp, struct io_sock_stream_send *send)
{
	return io_sock_stream_cancel_send(io_tcp_get_sock_stream(tcp), send);
}

static inline size_t
io_tcp_abort_send(io_tcp_t *tcp, struct io_sock_stream_send *send)
{
	return io_sock_stream_abort_send(io_tcp_get_sock_stream(tcp), send);
}

static inline ev_future_t *
io_tcp_async_send(io_tcp_t *tcp, ev_exec_t *exec, const void *buf,
		size_t nbytes, int flags, struct io_sock_stream_send **psend)
{
	return io_sock_stream_async_send(io_tcp_get_sock_stream(tcp), exec, buf,
			nbytes, flags, psend);
}

static inline int
io_tcp_shutdown(io_tcp_t *tcp, int how)
{
	return io_sock_stream_shutdown(io_tcp_get_sock_stream(tcp), how);
}

static inline int
io_tcp_get_keepalive(const io_tcp_t *tcp)
{
	return io_sock_stream_get_keepalive(io_tcp_get_sock_stream(tcp));
}

static inline int
io_tcp_set_keepalive(io_tcp_t *tcp, int optval)
{
	return io_sock_stream_set_keepalive(
			io_tcp_get_sock_stream(tcp), optval);
}

static inline int
io_tcp_get_linger(const io_tcp_t *tcp, int *ponoff, int *plinger)
{
	return io_sock_stream_get_linger(
			io_tcp_get_sock_stream(tcp), ponoff, plinger);
}

static inline int
io_tcp_set_linger(io_tcp_t *tcp, int onoff, int linger)
{
	return io_sock_stream_set_linger(
			io_tcp_get_sock_stream(tcp), onoff, linger);
}

static inline int
io_tcp_get_oobinline(const io_tcp_t *tcp)
{
	return io_sock_stream_get_oobinline(io_tcp_get_sock_stream(tcp));
}

static inline int
io_tcp_set_oobinline(io_tcp_t *tcp, int optval)
{
	return io_sock_stream_set_oobinline(
			io_tcp_get_sock_stream(tcp), optval);
}

static inline int
io_tcp_atmark(const io_tcp_t *tcp)
{
	return io_sock_stream_atmark(io_tcp_get_sock_stream(tcp));
}

static inline io_dev_t *
io_tcp_get_dev(const io_tcp_t *tcp)
{
	return io_sock_stream_get_dev(io_tcp_get_sock_stream(tcp));
}

static inline io_sock_t *
io_tcp_get_sock(const io_tcp_t *tcp)
{
	return io_sock_stream_get_sock(io_tcp_get_sock_stream(tcp));
}

static inline io_stream_t *
io_tcp_get_stream(const io_tcp_t *tcp)
{
	return io_sock_stream_get_stream(io_tcp_get_sock_stream(tcp));
}

inline io_sock_stream_t *
io_tcp_get_sock_stream(const io_tcp_t *tcp)
{
	return (*tcp)->get_sock_stream(tcp);
}

inline int
io_tcp_open_ipv4(io_tcp_t *tcp)
{
	return (*tcp)->open_ipv4(tcp);
}

inline int
io_tcp_open_ipv6(io_tcp_t *tcp, int v6only)
{
	return (*tcp)->open_ipv6(tcp, v6only);
}

inline int
io_tcp_get_nodelay(const io_tcp_t *tcp)
{
	return (*tcp)->get_nodelay(tcp);
}

inline int
io_tcp_set_nodelay(io_tcp_t *tcp, int optval)
{
	return (*tcp)->set_nodelay(tcp, optval);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_TCP_H_
