/**@file
 * This file is part of the I/O library; it contains the system TCP socket
 * implementation.
 *
 * @see lely/io2/sys/tcp.h
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

#include "../io2.h"

#if _WIN32 || (defined(_POSIX_C_SOURCE) && !defined(__NEWLIB__))

#include <lely/io2/sys/tcp.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

#if _POSIX_C_SOURCE
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#if _WIN32
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#endif

#include "sock_stream.h"
#include "sock_stream_srv.h"

static io_sock_stream_srv_t *io_tcp_srv_impl_get_sock_stream_srv(
		const io_tcp_srv_t *tcp);
static int io_tcp_srv_impl_open_ipv4(io_tcp_srv_t *tcp);
static int io_tcp_srv_impl_open_ipv6(io_tcp_srv_t *tcp, int v6only);

// clang-format off
static const struct io_tcp_srv_vtbl io_tcp_srv_impl_vtbl = {
	&io_tcp_srv_impl_get_sock_stream_srv,
	&io_tcp_srv_impl_open_ipv4,
	&io_tcp_srv_impl_open_ipv6
};
// clang-format on

/// The implementation of a TCP server.
struct io_tcp_srv_impl {
	/// A pointer to the virtual table for the TCP server interface.
	const struct io_tcp_srv_vtbl *tcp_srv_vptr;
	/// The stream server.
	struct io_sock_stream_srv_impl sock_stream_srv_impl;
};

static inline struct io_tcp_srv_impl *io_tcp_srv_impl_from_tcp_srv(
		const io_tcp_srv_t *tcp);
static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_tcp_srv(const io_tcp_srv_t *tcp);

static io_sock_stream_t *io_tcp_impl_get_sock_stream(const io_tcp_t *tcp);
static int io_tcp_impl_open_ipv4(io_tcp_t *tcp);
static int io_tcp_impl_open_ipv6(io_tcp_t *tcp, int v6only);
static int io_tcp_impl_get_nodelay(const io_tcp_t *tcp);
static int io_tcp_impl_set_nodelay(io_tcp_t *tcp, int optval);

// clang-format off
static const struct io_tcp_vtbl io_tcp_impl_vtbl = {
	&io_tcp_impl_get_sock_stream,
	&io_tcp_impl_open_ipv4,
	&io_tcp_impl_open_ipv6,
	&io_tcp_impl_get_nodelay,
	&io_tcp_impl_set_nodelay
};
// clang-format on

/// The implementation of a TCP socket.
struct io_tcp_impl {
	/// A pointer to the virtual table for the TCP socket interface.
	const struct io_tcp_vtbl *tcp_vptr;
	/// The stream socket.
	struct io_sock_stream_impl sock_stream_impl;
};

static inline struct io_tcp_impl *io_tcp_impl_from_tcp(const io_tcp_t *tcp);
static inline struct io_sock_stream_impl *io_sock_stream_impl_from_tcp(
		const io_tcp_t *tcp);

static int io_tcp_endp_load(struct io_endp *endp, const struct sockaddr *addr,
		socklen_t addrlen);
static int io_tcp_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen);
static int io_tcp_endp_store_any(int family, int protocol,
		struct sockaddr *addr, socklen_t *addrlen);

// clang-format off
static const struct io_endp_vtbl io_tcp_endp_vtbl = {
	&io_tcp_endp_load,
	&io_tcp_endp_store,
	&io_tcp_endp_store_any
};
// clang-format on

void *
io_tcp_srv_alloc(void)
{
	struct io_tcp_srv_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->tcp_srv_vptr;
}

void
io_tcp_srv_free(void *ptr)
{
	if (ptr)
		free(io_tcp_srv_impl_from_tcp_srv(ptr));
}

io_tcp_srv_t *
io_tcp_srv_init(io_tcp_srv_t *tcp, io_poll_t *poll, ev_exec_t *exec)
{
	io_tcp_srv_impl_from_tcp_srv(tcp)->tcp_srv_vptr = &io_tcp_srv_impl_vtbl;
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	// clang-format off
	return !io_sock_stream_srv_impl_init(impl, poll, exec,
			&io_tcp_endp_vtbl) ? tcp : NULL;
	// clang-format on
}

void
io_tcp_srv_fini(io_tcp_srv_t *tcp)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	io_sock_stream_srv_impl_fini(impl);
}

io_tcp_srv_t *
io_tcp_srv_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_tcp_srv_t *tcp = io_tcp_srv_alloc();
	if (!tcp) {
		errsv = get_errc();
		goto error_alloc;
	}

	io_tcp_srv_t *tmp = io_tcp_srv_init(tcp, poll, exec);
	if (!tmp) {
		errsv = get_errc();
		goto error_init;
	}
	tcp = tmp;

	return tcp;

error_init:
	io_tcp_srv_free((void *)tcp);
error_alloc:
	set_errc(errsv);
	return NULL;
}

void
io_tcp_srv_destroy(io_tcp_srv_t *tcp)
{
	if (tcp) {
		io_tcp_srv_fini(tcp);
		io_tcp_srv_free((void *)tcp);
	}
}

SOCKET
io_tcp_srv_get_handle(const io_tcp_srv_t *tcp)
{
	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	io_sock_stream_srv_impl_get_handle(
			io_sock_stream_srv_impl_from_tcp_srv(tcp), &handle);

	return handle.fd;
}

int
io_tcp_srv_assign(io_tcp_srv_t *tcp, SOCKET fd)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	struct io_sock_stream_srv_handle handle =
			IO_SOCK_STREAM_SRV_HANDLE_INIT;
	handle.fd = fd;
	handle.family = AF_INET;
	handle.protocol = IPPROTO_TCP;

#if _WIN32
	WSAPROTOCOL_INFOA ProtocolInfo = { .iAddressFamily = AF_UNSPEC };
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&ProtocolInfo,
			&(int){ sizeof(ProtocolInfo) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	handle.family = ProtocolInfo.iAddressFamily;
	handle.protocol = ProtocolInfo.iProtocol;
#else
#ifdef SO_DOMAIN
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &handle.family,
			&(socklen_t){ sizeof(handle.family) }) == -1)
		// clang-format on
		return -1;
#endif
#ifdef SO_PROTOCOL
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &handle.protocol,
			&(socklen_t){ sizeof(handle.protocol) }) == -1)
		// clang-format on
		return -1;
#endif
#endif

	if (handle.family != AF_INET && handle.family != AF_INET6) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	if (handle.protocol != IPPROTO_UDP) {
		WSASetLastError(WSAEPROTONOSUPPORT);
		return -1;
	}

	return io_sock_stream_srv_impl_assign(impl, &handle);
}

SOCKET
io_tcp_srv_release(io_tcp_srv_t *tcp)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	return io_sock_stream_srv_impl_release(impl);
}

void *
io_tcp_alloc(void)
{
	struct io_tcp_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->tcp_vptr;
}

void
io_tcp_free(void *ptr)
{
	if (ptr)
		free(io_tcp_impl_from_tcp(ptr));
}

io_tcp_t *
io_tcp_init(io_tcp_t *tcp, io_poll_t *poll, ev_exec_t *exec)
{
	io_tcp_impl_from_tcp(tcp)->tcp_vptr = &io_tcp_impl_vtbl;
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	return !io_sock_stream_impl_init(impl, poll, exec, &io_tcp_endp_vtbl)
			? tcp
			: NULL;
}

void
io_tcp_fini(io_tcp_t *tcp)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	io_sock_stream_impl_fini(impl);
}

io_tcp_t *
io_tcp_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_tcp_t *tcp = io_tcp_alloc();
	if (!tcp) {
		errsv = get_errc();
		goto error_alloc;
	}

	io_tcp_t *tmp = io_tcp_init(tcp, poll, exec);
	if (!tmp) {
		errsv = get_errc();
		goto error_init;
	}
	tcp = tmp;

	return tcp;

error_init:
	io_tcp_free((void *)tcp);
error_alloc:
	set_errc(errsv);
	return NULL;
}

void
io_tcp_destroy(io_tcp_t *tcp)
{
	if (tcp) {
		io_tcp_fini(tcp);
		io_tcp_free((void *)tcp);
	}
}

SOCKET
io_tcp_get_handle(const io_tcp_t *tcp)
{
	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	io_sock_stream_impl_get_handle(
			io_sock_stream_impl_from_tcp(tcp), &handle);

	return handle.fd;
}

int
io_tcp_assign(io_tcp_t *tcp, SOCKET fd)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	struct io_sock_stream_handle handle = IO_SOCK_STREAM_HANDLE_INIT;
	handle.fd = fd;
	handle.family = AF_INET;
	handle.protocol = IPPROTO_TCP;

#if _WIN32
	WSAPROTOCOL_INFOA ProtocolInfo = { .iAddressFamily = AF_UNSPEC };
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&ProtocolInfo,
			&(int){ sizeof(ProtocolInfo) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	handle.family = ProtocolInfo.iAddressFamily;
	handle.protocol = ProtocolInfo.iProtocol;
#else
#ifdef SO_DOMAIN
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &handle.family,
			&(socklen_t){ sizeof(handle.family) }) == -1)
		// clang-format on
		return -1;
#endif
#ifdef SO_PROTOCOL
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &handle.protocol,
			&(socklen_t){ sizeof(handle.protocol) }) == -1)
		// clang-format on
		return -1;
#endif
#endif

	if (handle.family != AF_INET && handle.family != AF_INET6) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}

	if (handle.protocol != IPPROTO_UDP) {
		WSASetLastError(WSAEPROTONOSUPPORT);
		return -1;
	}

	return io_sock_stream_impl_assign(impl, &handle);
}

SOCKET
io_tcp_release(io_tcp_t *tcp)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	return io_sock_stream_impl_release(impl);
}

static io_sock_stream_srv_t *
io_tcp_srv_impl_get_sock_stream_srv(const io_tcp_srv_t *tcp)
{
	const struct io_tcp_srv_impl *impl = io_tcp_srv_impl_from_tcp_srv(tcp);

	return &impl->sock_stream_srv_impl.sock_stream_srv_vptr;
}

static int
io_tcp_srv_impl_open_ipv4(io_tcp_srv_t *tcp)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	// clang-format off
	return io_sock_stream_srv_impl_open(impl, AF_INET, IPPROTO_TCP)
			!= INVALID_SOCKET ? 0 : -1;
	// clang-format on
}

static int
io_tcp_srv_impl_open_ipv6(io_tcp_srv_t *tcp, int v6only)
{
	struct io_sock_stream_srv_impl *impl =
			io_sock_stream_srv_impl_from_tcp_srv(tcp);

	int iError = 0;

	SOCKET fd = io_sock_stream_srv_impl_open(impl, AF_INET6, IPPROTO_TCP);
	if (fd == INVALID_SOCKET) {
		iError = WSAGetLastError();
		goto error_open;
	}

#if _WIN32
	DWORD optval = !!v6only;
#else
	int optval = !!v6only;
#endif
	// clang-format off
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&optval,
			sizeof(optval)) == SOCKET_ERROR) {
		// clang-format on
		iError = WSAGetLastError();
		goto error_setsockopt;
	}

	return 0;

error_setsockopt:
	io_sock_close(io_tcp_srv_get_sock(tcp));
error_open:
	WSASetLastError(iError);
	return -1;
}

static inline struct io_tcp_srv_impl *
io_tcp_srv_impl_from_tcp_srv(const io_tcp_srv_t *tcp)
{
	assert(tcp);

	return structof(tcp, struct io_tcp_srv_impl, tcp_srv_vptr);
}

static inline struct io_sock_stream_srv_impl *
io_sock_stream_srv_impl_from_tcp_srv(const io_tcp_srv_t *tcp)
{
	return &io_tcp_srv_impl_from_tcp_srv(tcp)->sock_stream_srv_impl;
}

static io_sock_stream_t *
io_tcp_impl_get_sock_stream(const io_tcp_t *tcp)
{
	const struct io_tcp_impl *impl = io_tcp_impl_from_tcp(tcp);

	return &impl->sock_stream_impl.sock_stream_vptr;
}

static int
io_tcp_impl_open_ipv4(io_tcp_t *tcp)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	// clang-format off
	return io_sock_stream_impl_open(impl, AF_INET, IPPROTO_TCP)
			!= INVALID_SOCKET ? 0 : -1;
	// clang-format on
}

static int
io_tcp_impl_open_ipv6(io_tcp_t *tcp, int v6only)
{
	struct io_sock_stream_impl *impl = io_sock_stream_impl_from_tcp(tcp);

	int iError = 0;

	SOCKET fd = io_sock_stream_impl_open(impl, AF_INET6, IPPROTO_TCP);
	if (fd == INVALID_SOCKET) {
		iError = WSAGetLastError();
		goto error_open;
	}

#if _WIN32
	DWORD optval = !!v6only;
#else
	int optval = !!v6only;
#endif
	// clang-format off
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&optval,
			sizeof(optval)) == SOCKET_ERROR) {
		// clang-format on
		iError = WSAGetLastError();
		goto error_setsockopt;
	}

	return 0;

error_setsockopt:
	io_sock_close(io_tcp_get_sock(tcp));
error_open:
	WSASetLastError(iError);
	return -1;
}

static int
io_tcp_impl_get_nodelay(const io_tcp_t *tcp)
{
	SOCKET fd = io_tcp_get_handle(tcp);

	int optval = 0;
	// clang-format off
	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval != 0;
}

static int
io_tcp_impl_set_nodelay(io_tcp_t *tcp, int optval)
{
	SOCKET fd = io_tcp_get_handle(tcp);

	optval = !!optval;
	// clang-format off
	return !setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

static inline struct io_tcp_impl *
io_tcp_impl_from_tcp(const io_tcp_t *tcp)
{
	assert(tcp);

	return structof(tcp, struct io_tcp_impl, tcp_vptr);
}

static inline struct io_sock_stream_impl *
io_sock_stream_impl_from_tcp(const io_tcp_t *tcp)
{
	return &io_tcp_impl_from_tcp(tcp)->sock_stream_impl;
}

static int
io_tcp_endp_load(struct io_endp *endp, const struct sockaddr *addr,
		socklen_t addrlen)
{
	assert(endp);
	assert(addr);

	if (addr->sa_family == AF_INET) {
		if (addrlen != sizeof(struct sockaddr_in)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct sockaddr_in *addr_in =
				(const struct sockaddr_in *)addr;

		int len = (int)sizeof(struct io_endp_ipv4_tcp);
		if ((endp->addr && endp->addr->family != IO_ADDR_IPV4)
				|| endp->len < len) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		struct io_endp_ipv4_tcp *ipv4_tcp =
				(struct io_endp_ipv4_tcp *)endp;
		*ipv4_tcp = (struct io_endp_ipv4_tcp)IO_ENDP_IPV4_TCP_INIT(
				ipv4_tcp);

		io_addr_ipv4_set_from_uint(&ipv4_tcp->ipv4,
				ntohl(addr_in->sin_addr.s_addr));
		ipv4_tcp->port = ntohs(addr_in->sin_port);

		return 0;
	} else if (addr->sa_family == AF_INET6) {
		if (addrlen != sizeof(struct sockaddr_in6)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct sockaddr_in6 *addr_in6 =
				(const struct sockaddr_in6 *)addr;

		int len = (int)sizeof(struct io_endp_ipv6_tcp);
		if ((endp->addr && endp->addr->family != IO_ADDR_IPV6)
				|| endp->len < len) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		struct io_endp_ipv6_tcp *ipv6_tcp =
				(struct io_endp_ipv6_tcp *)endp;
		*ipv6_tcp = (struct io_endp_ipv6_tcp)IO_ENDP_IPV6_TCP_INIT(
				ipv6_tcp);

		io_addr_ipv6_set_from_bytes(
				&ipv6_tcp->ipv6, addr_in6->sin6_addr.s6_addr);
		ipv6_tcp->ipv6.scope_id = addr_in6->sin6_scope_id;
		ipv6_tcp->port = ntohs(addr_in6->sin6_port);

		return 0;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
}

static int
io_tcp_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(endp);
	assert(addr);
	assert(addrlen);

	if (endp->addr && endp->addr->family == IO_ADDR_IPV4) {
		if (endp->len != sizeof(struct io_endp_ipv4_tcp)
				|| endp->protocol != IO_IPPROTO_TCP) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct io_endp_ipv4_tcp *ipv4_tcp =
				(const struct io_endp_ipv4_tcp *)endp;

		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		*addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		*addr_in = (struct sockaddr_in){ .sin_family = AF_INET };

		addr_in->sin_addr.s_addr =
				htonl(io_addr_ipv4_to_uint(&ipv4_tcp->ipv4));
		addr_in->sin_port = htons(ipv4_tcp->port);

		return 0;
	} else if (endp->addr && endp->addr->family == IO_ADDR_IPV6) {
		if (endp->len != sizeof(struct io_endp_ipv6_tcp)
				|| endp->protocol != IO_IPPROTO_TCP) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct io_endp_ipv6_tcp *ipv6_tcp =
				(const struct io_endp_ipv6_tcp *)endp;

		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		*addrlen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		*addr_in6 = (struct sockaddr_in6){ .sin6_family = AF_INET6 };

		io_addr_ipv6_to_bytes(
				&ipv6_tcp->ipv6, addr_in6->sin6_addr.s6_addr);
		addr_in6->sin6_scope_id = ipv6_tcp->ipv6.scope_id;
		addr_in6->sin6_port = htons(ipv6_tcp->port);

		return 0;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
}

static int
io_tcp_endp_store_any(int family, int protocol, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(addr);
	assert(addrlen);

	if (protocol != IPPROTO_TCP) {
		WSASetLastError(WSAEINVAL);
		return -1;
	}

	if (family == AF_INET) {
		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}

		*addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		*addr_in = (struct sockaddr_in){ .sin_family = AF_INET,
			.sin_addr.s_addr = INADDR_ANY };

		return 0;
	} else if (family == AF_INET6) {
		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}

		*addrlen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		*addr_in6 = (struct sockaddr_in6){ .sin6_family = AF_INET6,
			.sin6_addr = in6addr_any };

		return 0;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
}

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)
