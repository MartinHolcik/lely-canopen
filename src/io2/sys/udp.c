/**@file
 * This file is part of the I/O library; it contains the system UDP socket
 * implementation.
 *
 * @see lely/io2/sys/udp.h
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

#include <lely/io2/sys/udp.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

#if _POSIX_C_SOURCE
#include <netinet/in.h>
#endif

#if _WIN32
#include <ws2tcpip.h>
#endif

#include "sock_dgram.h"

static io_sock_dgram_t *io_udp_impl_get_sock_dgram(const io_udp_t *udp);
static int io_udp_impl_open_ipv4(io_udp_t *udp);
static int io_udp_impl_open_ipv6(io_udp_t *udp, int v6only);

// clang-format off
static const struct io_udp_vtbl io_udp_impl_vtbl = {
	&io_udp_impl_get_sock_dgram,
	&io_udp_impl_open_ipv4,
	&io_udp_impl_open_ipv6
};
// clang-format on

/// The implementation of a UDP socket.
struct io_udp_impl {
	/// A pointer to the virtual table for the UDP socket interface.
	const struct io_udp_vtbl *udp_vptr;
	/// The datagram socket.
	struct io_sock_dgram_impl sock_dgram_impl;
};

static inline struct io_udp_impl *io_udp_impl_from_udp(const io_udp_t *udp);
static inline struct io_sock_dgram_impl *io_sock_dgram_impl_from_udp(
		const io_udp_t *udp);

static int io_udp_endp_load(struct io_endp *endp, const struct sockaddr *addr,
		socklen_t addrlen);
static int io_udp_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen);
static int io_udp_endp_store_any(int family, int protocol,
		struct sockaddr *addr, socklen_t *addrlen);

// clang-format off
static const struct io_endp_vtbl io_udp_endp_vtbl = {
	&io_udp_endp_load,
	&io_udp_endp_store,
	&io_udp_endp_store_any
};
// clang-format on

void *
io_udp_alloc(void)
{
	struct io_udp_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return NULL;
	}
	return &impl->udp_vptr;
}

void
io_udp_free(void *ptr)
{
	if (ptr)
		free(io_udp_impl_from_udp(ptr));
}

io_udp_t *
io_udp_init(io_udp_t *udp, io_poll_t *poll, ev_exec_t *exec)
{
	io_udp_impl_from_udp(udp)->udp_vptr = &io_udp_impl_vtbl;
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	return !io_sock_dgram_impl_init(impl, poll, exec, &io_udp_endp_vtbl)
			? udp
			: NULL;
}

void
io_udp_fini(io_udp_t *udp)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	io_sock_dgram_impl_fini(impl);
}

io_udp_t *
io_udp_create(io_poll_t *poll, ev_exec_t *exec)
{
	int errsv = 0;

	io_udp_t *udp = io_udp_alloc();
	if (!udp) {
		errsv = get_errc();
		goto error_alloc;
	}

	io_udp_t *tmp = io_udp_init(udp, poll, exec);
	if (!tmp) {
		errsv = get_errc();
		goto error_init;
	}
	udp = tmp;

	return udp;

error_init:
	io_udp_free((void *)udp);
error_alloc:
	set_errc(errsv);
	return NULL;
}

void
io_udp_destroy(io_udp_t *udp)
{
	if (udp) {
		io_udp_fini(udp);
		io_udp_free((void *)udp);
	}
}

SOCKET
io_udp_get_handle(const io_udp_t *udp)
{
	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	io_sock_dgram_impl_get_handle(
			io_sock_dgram_impl_from_udp(udp), &handle);

	return handle.fd;
}

int
io_udp_assign(io_udp_t *udp, SOCKET fd)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	struct io_sock_dgram_handle handle = IO_SOCK_DGRAM_HANDLE_INIT;
	handle.fd = fd;
	handle.family = AF_INET;
	handle.protocol = IPPROTO_UDP;

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

	return io_sock_dgram_impl_assign(impl, &handle);
}

SOCKET
io_udp_release(io_udp_t *udp)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	return io_sock_dgram_impl_release(impl);
}

static io_sock_dgram_t *
io_udp_impl_get_sock_dgram(const io_udp_t *udp)
{
	const struct io_udp_impl *impl = io_udp_impl_from_udp(udp);

	return &impl->sock_dgram_impl.sock_dgram_vptr;
}

static int
io_udp_impl_open_ipv4(io_udp_t *udp)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	// clang-format off
	return io_sock_dgram_impl_open(impl, AF_INET, IPPROTO_UDP)
			!= INVALID_SOCKET ? 0 : -1;
	// clang-format on
}

static int
io_udp_impl_open_ipv6(io_udp_t *udp, int v6only)
{
	struct io_sock_dgram_impl *impl = io_sock_dgram_impl_from_udp(udp);

	int iError = 0;

	SOCKET fd = io_sock_dgram_impl_open(impl, AF_INET6, IPPROTO_UDP);
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
	io_sock_close(io_udp_get_sock(udp));
error_open:
	WSASetLastError(iError);
	return -1;
}

static inline struct io_udp_impl *
io_udp_impl_from_udp(const io_udp_t *udp)
{
	assert(udp);

	return structof(udp, struct io_udp_impl, udp_vptr);
}

static inline struct io_sock_dgram_impl *
io_sock_dgram_impl_from_udp(const io_udp_t *udp)
{
	return &io_udp_impl_from_udp(udp)->sock_dgram_impl;
}

static int
io_udp_endp_load(struct io_endp *endp, const struct sockaddr *addr,
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

		int len = (int)sizeof(struct io_endp_ipv4_udp);
		if ((endp->addr && endp->addr->family != IO_ADDR_IPV4)
				|| endp->len < len) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		struct io_endp_ipv4_udp *ipv4_udp =
				(struct io_endp_ipv4_udp *)endp;
		*ipv4_udp = (struct io_endp_ipv4_udp)IO_ENDP_IPV4_UDP_INIT(
				ipv4_udp);

		io_addr_ipv4_set_from_uint(&ipv4_udp->ipv4,
				ntohl(addr_in->sin_addr.s_addr));
		ipv4_udp->port = ntohs(addr_in->sin_port);

		return 0;
	} else if (addr->sa_family == AF_INET6) {
		if (addrlen != sizeof(struct sockaddr_in6)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct sockaddr_in6 *addr_in6 =
				(const struct sockaddr_in6 *)addr;

		int len = (int)sizeof(struct io_endp_ipv6_udp);
		if ((endp->addr && endp->addr->family != IO_ADDR_IPV6)
				|| endp->len < len) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		struct io_endp_ipv6_udp *ipv6_udp =
				(struct io_endp_ipv6_udp *)endp;
		*ipv6_udp = (struct io_endp_ipv6_udp)IO_ENDP_IPV6_UDP_INIT(
				ipv6_udp);

		io_addr_ipv6_set_from_bytes(
				&ipv6_udp->ipv6, addr_in6->sin6_addr.s6_addr);
		ipv6_udp->ipv6.scope_id = addr_in6->sin6_scope_id;
		ipv6_udp->port = ntohs(addr_in6->sin6_port);

		return 0;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
}

static int
io_udp_endp_store(const struct io_endp *endp, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(endp);
	assert(addr);
	assert(addrlen);

	if (endp->addr && endp->addr->family == IO_ADDR_IPV4) {
		if (endp->len != sizeof(struct io_endp_ipv4_udp)
				|| endp->protocol != IO_IPPROTO_UDP) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct io_endp_ipv4_udp *ipv4_udp =
				(const struct io_endp_ipv4_udp *)endp;

		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		*addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		*addr_in = (struct sockaddr_in){ .sin_family = AF_INET };

		addr_in->sin_addr.s_addr =
				htonl(io_addr_ipv4_to_uint(&ipv4_udp->ipv4));
		addr_in->sin_port = htons(ipv4_udp->port);

		return 0;
	} else if (endp->addr && endp->addr->family == IO_ADDR_IPV6) {
		if (endp->len != sizeof(struct io_endp_ipv6_udp)
				|| endp->protocol != IO_IPPROTO_UDP) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		const struct io_endp_ipv6_udp *ipv6_udp =
				(const struct io_endp_ipv6_udp *)endp;

		if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6)) {
			WSASetLastError(WSAEINVAL);
			return -1;
		}
		*addrlen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		*addr_in6 = (struct sockaddr_in6){ .sin6_family = AF_INET6 };

		io_addr_ipv6_to_bytes(
				&ipv6_udp->ipv6, addr_in6->sin6_addr.s6_addr);
		addr_in6->sin6_scope_id = ipv6_udp->ipv6.scope_id;
		addr_in6->sin6_port = htons(ipv6_udp->port);

		return 0;
	} else {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
}

static int
io_udp_endp_store_any(int family, int protocol, struct sockaddr *addr,
		socklen_t *addrlen)
{
	assert(addr);
	assert(addrlen);

	if (protocol != IPPROTO_UDP) {
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
