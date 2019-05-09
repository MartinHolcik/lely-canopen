/**@file
 * This header file is part of the I/O library; it contains the abstract UDP
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

#ifndef LELY_IO2_UDP_H_
#define LELY_IO2_UDP_H_

#include <lely/io2/endp.h>
#include <lely/io2/ipv4.h>
#include <lely/io2/ipv6.h>
#include <lely/io2/sock_dgram.h>

#ifndef LELY_IO_UDP_INLINE
#define LELY_IO_UDP_INLINE static inline
#endif

/// The IANA protocol number for UDP.
#define IO_IPPROTO_UDP 17

/// An IPv4 UDP endpoint.
struct io_endp_ipv4_udp {
	/// &#ipv4
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv4_udp)`
	int len;
	/// #IO_IPPROTO_UDP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv4 network address.
	struct io_addr_ipv4 ipv4;
};

/**
 * The static initializer for #io_endp_ipv4_udp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV4_UDP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv4, \
				sizeof(struct io_endp_ipv4_udp), \
				IO_IPPROTO_UDP, 0, IO_ADDR_IPV4_INIT \
	}

union io_endp_ipv4_udp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv4_udp _ipv4_udp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv4 UDP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV4_UDP_STRLEN (IO_ADDR_IPV4_STRLEN + 6)

/// An IPv6 UDP endpoint.
struct io_endp_ipv6_udp {
	/// &#ipv6
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv6_udp)`
	int len;
	/// #IO_IPPROTO_UDP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv6 network address.
	struct io_addr_ipv6 ipv6;
};

/**
 * The static initializer for #io_endp_ipv6_udp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV6_UDP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv6, \
				sizeof(struct io_endp_ipv6_udp), \
				IO_IPPROTO_UDP, 0, IO_ADDR_IPV6_INIT \
	}

union io_endp_ipv6_udp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv6_udp _ipv6_udp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv6 UDP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV6_UDP_STRLEN (IO_ADDR_IPV6_STRLEN + 8)

/// An abstract UDP socket.
typedef const struct io_udp_vtbl *const io_udp_t;

#ifdef __cplusplus
extern "C" {
#endif

struct io_udp_vtbl {
	io_sock_dgram_t *(*get_sock_dgram)(const io_udp_t *udp);
	int (*open_ipv4)(io_udp_t *udp);
	int (*open_ipv6)(io_udp_t *udp, int v6only);
};

/**
 * Creates an IPv4 UDP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv4_udp_to_string()
 */
int io_endp_ipv4_udp_set_from_string(
		struct io_endp_ipv4_udp *endp, const char *str);

/**
 * Stores a text representation of the IPv4 UDP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV4_UDP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv4_udp_to_string()
 */
void io_endp_ipv4_udp_to_string(const struct io_endp_ipv4_udp *endp, char *str);

/**
 * Creates an IPv6 UDP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv6_udp_to_string()
 */
int io_endp_ipv6_udp_set_from_string(
		struct io_endp_ipv6_udp *endp, const char *str);

/**
 * Stores a text representation of the IPv6 UDP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV6_UDP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv6_udp_to_string()
 */
void io_endp_ipv6_udp_to_string(const struct io_endp_ipv6_udp *endp, char *str);

/// @see io_dev_get_ctx()
static inline io_ctx_t *io_udp_get_ctx(const io_udp_t *udp);

/// @see io_dev_get_exec()
static inline ev_exec_t *io_udp_get_exec(const io_udp_t *udp);

/// @see io_dev_cancel()
static inline size_t io_udp_cancel(io_udp_t *udp, struct ev_task *task);

/// @see io_dev_abort()
static inline size_t io_udp_abort(io_udp_t *udp, struct ev_task *task);

/// @see io_sock_bind()
static inline int io_udp_bind(
		io_udp_t *udp, const struct io_endp *endp, int reuseaddr);

/// @see io_sock_getsockname()
static inline int io_udp_getsockname(const io_udp_t *udp, struct io_endp *endp);

/// @see io_sock_is_open()
static inline int io_udp_is_open(const io_udp_t *udp);

/// @see io_sock_close()
static inline int io_udp_close(io_udp_t *udp);

/// @see io_sock_wait()
static inline int io_udp_wait(io_udp_t *udp, int *events, int timeout);

/// @see io_sock_submit_wait()
static inline void io_udp_submit_wait(io_udp_t *udp, struct io_sock_wait *wait);

/// @see io_sock_cancel_wait()
static inline size_t io_udp_cancel_wait(
		io_udp_t *udp, struct io_sock_wait *wait);

/// @see io_sock_abort_wait()
static inline size_t io_udp_abort_wait(
		io_udp_t *udp, struct io_sock_wait *wait);

/// @see io_sock_async_wait()
static inline ev_future_t *io_udp_async_wait(io_udp_t *udp, ev_exec_t *exec,
		int *events, struct io_sock_wait **pwait);

/// @see io_sock_get_error()
static inline int io_udp_get_error(io_udp_t *udp);

/// @see io_sock_get_nread()
static inline int io_udp_get_nread(const io_udp_t *udp);

/// @see io_sock_get_dontroute()
static inline int io_udp_get_dontroute(const io_udp_t *udp);

/// @see io_sock_set_dontroute()
static inline int io_udp_set_dontroute(io_udp_t *udp, int optval);

/// @see io_sock_get_rcvbuf()
static inline int io_udp_get_rcvbuf(const io_udp_t *udp);

/// @see io_sock_set_rcvbuf()
static inline int io_udp_set_rcvbuf(io_udp_t *udp, int optval);

/// @see io_sock_get_sndbuf()
static inline int io_udp_get_sndbuf(const io_udp_t *udp);

/// @see io_sock_set_sndbuf()
static inline int io_udp_set_sndbuf(io_udp_t *udp, int optval);

/// @see io_sock_dgram_connect()
static inline int io_udp_connect(io_udp_t *udp, const struct io_endp *endp);

/// @see io_sock_dgram_getpeername()
static inline int io_udp_getpeername(const io_udp_t *udp, struct io_endp *endp);

/// @see io_sock_dgram_recvmsg()
static inline ssize_t io_udp_recvmsg(io_udp_t *udp, const struct io_buf *buf,
		int bufcnt, int *flags, struct io_endp *endp, int timeout);

/// @see io_sock_dgram_submit_recvmsg()
static inline void io_udp_submit_recvmsg(
		io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg);

/// @see io_sock_dgram_cancel_recvmsg()
static inline size_t io_udp_cancel_recvmsg(
		io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg);

/// @see io_sock_dgram_abort_recvmsg()
static inline size_t io_udp_abort_recvmsg(
		io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg);

/// @see io_sock_dgram_async_recvmsg()
static inline ev_future_t *io_udp_async_recvmsg(io_udp_t *udp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, struct io_sock_dgram_recvmsg **precvmsg);

/// @see io_sock_dgram_recvfrom()
static inline ssize_t io_udp_recvfrom(io_udp_t *udp, void *buf, size_t nbytes,
		int *flags, struct io_endp *endp, int timeout);

/// @see io_sock_dgram_submit_recvfrom()
static inline void io_udp_submit_recvfrom(
		io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom);

/// @see io_sock_dgram_cancel_recvfrom()
static inline size_t io_udp_cancel_recvfrom(
		io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom);

/// @see io_sock_dgram_abort_recvfrom()
static inline size_t io_udp_abort_recvfrom(
		io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom);

/// @see io_sock_dgram_async_recvfrom()
static inline ev_future_t *io_udp_async_recvfrom(io_udp_t *udp, ev_exec_t *exec,
		void *buf, size_t nbytes, int *flags, struct io_endp *endp,
		struct io_sock_dgram_recvfrom **precvfrom);

/// @see io_sock_dgram_sendmsg()
static inline ssize_t io_udp_sendmsg(io_udp_t *udp, const struct io_buf *buf,
		int bufcnt, int flags, const struct io_endp *endp, int timeout);

/// @see io_sock_dgram_submit_sendmsg()
static inline void io_udp_submit_sendmsg(
		io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg);

/// @see io_sock_dgram_cancel_sendmsg()
static inline size_t io_udp_cancel_sendmsg(
		io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg);

/// @see io_sock_dgram_abort_sendmsg()
static inline size_t io_udp_abort_sendmsg(
		io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg);

/// @see io_sock_dgram_async_sendmsg()
static inline ev_future_t *io_udp_async_sendmsg(io_udp_t *udp, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendmsg **psendmsg);

/// @see io_sock_dgram_sendto()
static inline ssize_t io_udp_sendto(io_udp_t *udp, const void *buf,
		size_t nbytes, int flags, const struct io_endp *endp,
		int timeout);

/// @see io_sock_dgram_submit_sendto()
static inline void io_udp_submit_sendto(
		io_udp_t *udp, struct io_sock_dgram_sendto *sendto);

/// @see io_sock_dgram_cancel_sendto()
static inline size_t io_udp_cancel_sendto(
		io_udp_t *udp, struct io_sock_dgram_sendto *sendto);

/// @see io_sock_dgram_abort_sendto()
static inline size_t io_udp_abort_sendto(
		io_udp_t *udp, struct io_sock_dgram_sendto *sendto);

/// @see io_sock_dgram_async_sendto()
static inline ev_future_t *io_udp_async_sendto(io_udp_t *udp, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendto **psendto);

/// @see io_sock_dgram_get_broadcast()
static inline int io_udp_get_broadcast(const io_udp_t *udp);

/// @see io_sock_dgram_set_broadcast()
static inline int io_udp_set_broadcast(io_udp_t *udp, int optval);

/// Returns a pointer to the abstract I/O device representing the UDP socket.
static inline io_dev_t *io_udp_get_dev(const io_udp_t *udp);

/// Returns a pointer to the abstract socket representing the UDP socket.
static inline io_sock_t *io_udp_get_sock(const io_udp_t *udp);

/**
 * Returns a pointer to the abstract datagram socket representing the UDP
 * socket.
 */
LELY_IO_UDP_INLINE io_sock_dgram_t *io_udp_get_sock_dgram(const io_udp_t *udp);

/**
 * Opens an IPv4 UDP socket as if by POSIX
 * `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_UDP_INLINE int io_udp_open_ipv4(io_udp_t *udp);

/**
 * Opens an IPv6 UDP socket as if by POSIX
 * `socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`. If <b>v6only</b> is non-zero,
 * and the implemenation supports dual stack, the resulting socket can also be
 * used for IPv4 communication.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
LELY_IO_UDP_INLINE int io_udp_open_ipv6(io_udp_t *udp, int v6only);

static inline io_ctx_t *
io_udp_get_ctx(const io_udp_t *udp)
{
	return io_dev_get_ctx(io_udp_get_dev(udp));
}

static inline ev_exec_t *
io_udp_get_exec(const io_udp_t *udp)
{
	return io_dev_get_exec(io_udp_get_dev(udp));
}

static inline size_t
io_udp_cancel(io_udp_t *udp, struct ev_task *task)
{
	return io_dev_cancel(io_udp_get_dev(udp), task);
}

static inline size_t
io_udp_abort(io_udp_t *udp, struct ev_task *task)
{
	return io_dev_abort(io_udp_get_dev(udp), task);
}

static inline int
io_udp_bind(io_udp_t *udp, const struct io_endp *endp, int reuseaddr)
{
	return io_sock_bind(io_udp_get_sock(udp), endp, reuseaddr);
}

static inline int
io_udp_getsockname(const io_udp_t *udp, struct io_endp *endp)
{
	return io_sock_getsockname(io_udp_get_sock(udp), endp);
}

static inline int
io_udp_is_open(const io_udp_t *udp)
{
	return io_sock_is_open(io_udp_get_sock(udp));
}

static inline int
io_udp_close(io_udp_t *udp)
{
	return io_sock_close(io_udp_get_sock(udp));
}

static inline int
io_udp_wait(io_udp_t *udp, int *events, int timeout)
{
	return io_sock_wait(io_udp_get_sock(udp), events, timeout);
}

static inline void
io_udp_submit_wait(io_udp_t *udp, struct io_sock_wait *wait)
{
	io_sock_submit_wait(io_udp_get_sock(udp), wait);
}

static inline size_t
io_udp_cancel_wait(io_udp_t *udp, struct io_sock_wait *wait)
{
	return io_sock_cancel_wait(io_udp_get_sock(udp), wait);
}

static inline size_t
io_udp_abort_wait(io_udp_t *udp, struct io_sock_wait *wait)
{
	return io_sock_abort_wait(io_udp_get_sock(udp), wait);
}

static inline ev_future_t *
io_udp_async_wait(io_udp_t *udp, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	return io_sock_async_wait(io_udp_get_sock(udp), exec, events, pwait);
}

static inline int
io_udp_get_error(io_udp_t *udp)
{
	return io_sock_get_error(io_udp_get_sock(udp));
}

static inline int
io_udp_get_nread(const io_udp_t *udp)
{
	return io_sock_get_nread(io_udp_get_sock(udp));
}

static inline int
io_udp_get_dontroute(const io_udp_t *udp)
{
	return io_sock_get_dontroute(io_udp_get_sock(udp));
}

static inline int
io_udp_set_dontroute(io_udp_t *udp, int optval)
{
	return io_sock_set_dontroute(io_udp_get_sock(udp), optval);
}

static inline int
io_udp_get_rcvbuf(const io_udp_t *udp)
{
	return io_sock_get_rcvbuf(io_udp_get_sock(udp));
}

static inline int
io_udp_set_rcvbuf(io_udp_t *udp, int optval)
{
	return io_sock_set_rcvbuf(io_udp_get_sock(udp), optval);
}

static inline int
io_udp_get_sndbuf(const io_udp_t *udp)
{
	return io_sock_get_sndbuf(io_udp_get_sock(udp));
}

static inline int
io_udp_set_sndbuf(io_udp_t *udp, int optval)
{
	return io_sock_set_sndbuf(io_udp_get_sock(udp), optval);
}

static inline int
io_udp_connect(io_udp_t *udp, const struct io_endp *endp)
{
	return io_sock_dgram_connect(io_udp_get_sock_dgram(udp), endp);
}

static inline int
io_udp_getpeername(const io_udp_t *udp, struct io_endp *endp)
{
	return io_sock_dgram_getpeername(io_udp_get_sock_dgram(udp), endp);
}

static inline ssize_t
io_udp_recvmsg(io_udp_t *udp, const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, int timeout)
{
	return io_sock_dgram_recvmsg(io_udp_get_sock_dgram(udp), buf, bufcnt,
			flags, endp, timeout);
}

static inline void
io_udp_submit_recvmsg(io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg)
{
	io_sock_dgram_submit_recvmsg(io_udp_get_sock_dgram(udp), recvmsg);
}

static inline size_t
io_udp_cancel_recvmsg(io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg)
{
	return io_sock_dgram_cancel_recvmsg(
			io_udp_get_sock_dgram(udp), recvmsg);
}

static inline size_t
io_udp_abort_recvmsg(io_udp_t *udp, struct io_sock_dgram_recvmsg *recvmsg)
{
	return io_sock_dgram_abort_recvmsg(io_udp_get_sock_dgram(udp), recvmsg);
}

static inline ev_future_t *
io_udp_async_recvmsg(io_udp_t *udp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, int *flags, struct io_endp *endp,
		struct io_sock_dgram_recvmsg **precvmsg)
{
	return io_sock_dgram_async_recvmsg(io_udp_get_sock_dgram(udp), exec,
			buf, bufcnt, flags, endp, precvmsg);
}

static inline ssize_t
io_udp_recvfrom(io_udp_t *udp, void *buf, size_t nbytes, int *flags,
		struct io_endp *endp, int timeout)
{
	return io_sock_dgram_recvfrom(io_udp_get_sock_dgram(udp), buf, nbytes,
			flags, endp, timeout);
}

static inline void
io_udp_submit_recvfrom(io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom)
{
	io_sock_dgram_submit_recvfrom(io_udp_get_sock_dgram(udp), recvfrom);
}

static inline size_t
io_udp_cancel_recvfrom(io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom)
{
	return io_sock_dgram_cancel_recvfrom(
			io_udp_get_sock_dgram(udp), recvfrom);
}

static inline size_t
io_udp_abort_recvfrom(io_udp_t *udp, struct io_sock_dgram_recvfrom *recvfrom)
{
	return io_sock_dgram_abort_recvfrom(
			io_udp_get_sock_dgram(udp), recvfrom);
}

static inline ev_future_t *
io_udp_async_recvfrom(io_udp_t *udp, ev_exec_t *exec, void *buf, size_t nbytes,
		int *flags, struct io_endp *endp,
		struct io_sock_dgram_recvfrom **precvfrom)
{
	return io_sock_dgram_async_recvfrom(io_udp_get_sock_dgram(udp), exec,
			buf, nbytes, flags, endp, precvfrom);
}

static inline ssize_t
io_udp_sendmsg(io_udp_t *udp, const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp, int timeout)
{
	return io_sock_dgram_sendmsg(io_udp_get_sock_dgram(udp), buf, bufcnt,
			flags, endp, timeout);
}

static inline void
io_udp_submit_sendmsg(io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg)
{
	io_sock_dgram_submit_sendmsg(io_udp_get_sock_dgram(udp), sendmsg);
}

static inline size_t
io_udp_cancel_sendmsg(io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg)
{
	return io_sock_dgram_cancel_sendmsg(
			io_udp_get_sock_dgram(udp), sendmsg);
}

static inline size_t
io_udp_abort_sendmsg(io_udp_t *udp, struct io_sock_dgram_sendmsg *sendmsg)
{
	return io_sock_dgram_abort_sendmsg(io_udp_get_sock_dgram(udp), sendmsg);
}

static inline ev_future_t *
io_udp_async_sendmsg(io_udp_t *udp, ev_exec_t *exec, const struct io_buf *buf,
		int bufcnt, int flags, const struct io_endp *endp,
		struct io_sock_dgram_sendmsg **psendmsg)
{
	return io_sock_dgram_async_sendmsg(io_udp_get_sock_dgram(udp), exec,
			buf, bufcnt, flags, endp, psendmsg);
}

static inline ssize_t
io_udp_sendto(io_udp_t *udp, const void *buf, size_t nbytes, int flags,
		const struct io_endp *endp, int timeout)
{
	return io_sock_dgram_sendto(io_udp_get_sock_dgram(udp), buf, nbytes,
			flags, endp, timeout);
}

static inline void
io_udp_submit_sendto(io_udp_t *udp, struct io_sock_dgram_sendto *sendto)
{
	io_sock_dgram_submit_sendto(io_udp_get_sock_dgram(udp), sendto);
}

static inline size_t
io_udp_cancel_sendto(io_udp_t *udp, struct io_sock_dgram_sendto *sendto)
{
	return io_sock_dgram_cancel_sendto(io_udp_get_sock_dgram(udp), sendto);
}

static inline size_t
io_udp_abort_sendto(io_udp_t *udp, struct io_sock_dgram_sendto *sendto)
{
	return io_sock_dgram_abort_sendto(io_udp_get_sock_dgram(udp), sendto);
}

static inline ev_future_t *
io_udp_async_sendto(io_udp_t *udp, ev_exec_t *exec, const void *buf,
		size_t nbytes, int flags, const struct io_endp *endp,
		struct io_sock_dgram_sendto **psendto)
{
	return io_sock_dgram_async_sendto(io_udp_get_sock_dgram(udp), exec, buf,
			nbytes, flags, endp, psendto);
}

static inline int
io_udp_get_broadcast(const io_udp_t *udp)
{
	return io_sock_dgram_get_broadcast(io_udp_get_sock_dgram(udp));
}

static inline int
io_udp_set_broadcast(io_udp_t *udp, int optval)
{
	return io_sock_dgram_set_broadcast(io_udp_get_sock_dgram(udp), optval);
}

static inline io_dev_t *
io_udp_get_dev(const io_udp_t *udp)
{
	return io_sock_dgram_get_dev(io_udp_get_sock_dgram(udp));
}

static inline io_sock_t *
io_udp_get_sock(const io_udp_t *udp)
{
	return io_sock_dgram_get_sock(io_udp_get_sock_dgram(udp));
}

inline io_sock_dgram_t *
io_udp_get_sock_dgram(const io_udp_t *udp)
{
	return (*udp)->get_sock_dgram(udp);
}

inline int
io_udp_open_ipv4(io_udp_t *udp)
{
	return (*udp)->open_ipv4(udp);
}

inline int
io_udp_open_ipv6(io_udp_t *udp, int v6only)
{
	return (*udp)->open_ipv6(udp, v6only);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_UDP_H_
