/**@file
 * This file is part of the I/O library; it contains the implementation of the
 * common socket functions.
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

#include "sock.h"

#if _WIN32 || (defined(_POSIX_C_SOURCE) && !defined(__NEWLIB__))

#include <lely/io2/sock.h>

#include <assert.h>

#ifdef _POSIX_C_SOURCE
#include <fcntl.h>
#include <poll.h>
#endif

#ifndef LELY_HAVE_IOCTL
#if defined(__linux__) || defined(BSD)
#define LELY_HAVE_IOCTL 1
#endif
#endif

#if LELY_HAVE_IOCTL
#include <sys/ioctl.h>
#define ioctlsocket ioctl
#endif

#ifdef _POSIX_C_SOURCE
#include "../posix/fd.h"
#endif
#if _WIN32
#include "../win32/wsa.h"
#endif

#if _WIN32
int
io_sock_fd_init(SOCKET fd, SOCKET *pbase, int *pfamily, int *pprotocol,
		int *pskip_iocp)
{
	WSAPROTOCOL_INFOA ProtocolInfo = { .iAddressFamily = AF_UNSPEC };
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL_INFOA, (char *)&ProtocolInfo,
			&(int){ sizeof(ProtocolInfo) }) == SOCKET_ERROR)
		// clang-format on
		return -1;

	SOCKET base = fd;
	if (!(ProtocolInfo.dwServiceFlags1 & XP1_IFS_HANDLES)) {
		base = io_wsa_base_handle(fd);
		if (base == INVALID_SOCKET)
			return -1;
	}

	int skip_iocp = 0;
	UCHAR Flags = FILE_SKIP_SET_EVENT_ON_HANDLE;
#if !LELY_NO_IO_SKIP_IOCP
	// SetFileCompletionNotificationModes API causes an I/O completion port
	// not to work correctly if a non-IFS LSP is installed:
	// https://support.microsoft.com/en-us/help/2568167/setfilecompletionnotificationmodes-api-causes-an-i-o-completion-port-n
	if (ProtocolInfo.dwServiceFlags1 & XP1_IFS_HANDLES) {
		skip_iocp = 1;
		Flags |= FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
	}
#endif
	if (!SetFileCompletionNotificationModes((HANDLE)fd, Flags))
		return -1;

	if (pbase)
		*pbase = base;

	if (pfamily)
		*pfamily = ProtocolInfo.iAddressFamily;

	if (pprotocol)
		*pprotocol = ProtocolInfo.iProtocol;

	if (pskip_iocp)
		*pskip_iocp = skip_iocp;

	return 0;
}
#endif // _WIN32

int
io_sock_fd_bind(SOCKET fd, int family, int protocol,
		const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int reuseaddr)
{
	assert(endp_vptr);
	assert(endp_vptr->store);
	assert(endp_vptr->store_any);

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);
	if (endp) {
		if (endp_vptr->store(endp, (struct sockaddr *)&addr, &addrlen)
				== -1)
			return -1;
	} else {
		// clang-format off
		if (endp_vptr->store_any(family, protocol,
				(struct sockaddr *)&addr, &addrlen) == -1)
			// clang-format on
			return -1;
	}

	int optval = 1;
	// clang-format off
#if defined(SO_REUSEPORT) && !defined(__linux__)
	if (reuseaddr && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
#else
	if (reuseaddr && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
#endif
			(void *)&optval, sizeof(optval)) == -1)
		// clang-format on
		return -1;

	return !bind(fd, (const struct sockaddr *)&addr, addrlen) ? 0 : -1;
}

int
io_sock_fd_getsockname(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp)
{
	assert(endp_vptr);
	assert(endp_vptr->load);

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);

	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
		return -1;

	if (!endp)
		return 0;
	return endp_vptr->load(endp, (const struct sockaddr *)&addr, addrlen);
}

int
io_sock_fd_wait(SOCKET fd, int *events, int timeout)
{
	assert(events);

	int events_ = 0;
	if (*events & IO_EVENT_IN)
		events_ |= POLLRDNORM;
	if (*events & IO_EVENT_PRI)
		events_ |= POLLRDBAND | POLLPRI;
	if (*events & IO_EVENT_OUT)
		events_ |= POLLOUT;
	*events = 0;

#if _WIN32
	if (io_wsa_wait(fd, &events_, timeout) == -1)
#else
	if (io_fd_wait(fd, &events_, timeout) == -1)
#endif
		return -1;

	if (events_ & POLLRDNORM)
		*events |= IO_EVENT_IN;
	if (events_ & (POLLRDBAND | POLLPRI))
		*events |= IO_EVENT_PRI;
	if (events_ & POLLOUT)
		*events |= IO_EVENT_OUT;
	if (events_ & POLLERR)
		*events |= IO_EVENT_ERR;
	if (events_ & POLLHUP)
		*events |= IO_EVENT_HUP;

	return 0;
}

SOCKET
io_sock_fd_accept(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp, int timeout)
{
	assert(endp_vptr);
	assert(endp_vptr->load);

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);

#if _WIN32
	fd = io_wsa_accept(fd, endp ? (struct sockaddr *)&addr : NULL,
			endp ? &addrlen : NULL, timeout);
#else
	fd = io_fd_accept(fd, O_CLOEXEC | O_NONBLOCK,
			endp ? (struct sockaddr *)&addr : NULL,
			endp ? &addrlen : NULL, timeout);
#endif
	if (fd == INVALID_SOCKET)
		return INVALID_SOCKET;

	if (endp)
		endp_vptr->load(endp, (struct sockaddr *)&addr, addrlen);

	return fd;
}

int
io_sock_fd_connect(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int dontwait)
{
	assert(endp_vptr);
	assert(endp_vptr->store);

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);
	if (endp) {
		if (endp_vptr->store(endp, (struct sockaddr *)&addr, &addrlen)
				== -1)
			return -1;
	} else {
		addrlen = sizeof(struct sockaddr);
	}

#if _WIN32
	return io_wsa_connect(
			fd, (const struct sockaddr *)&addr, addrlen, dontwait);
#else
	return io_fd_connect(
			fd, (const struct sockaddr *)&addr, addrlen, dontwait);
#endif
}

int
io_sock_fd_getpeername(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp)
{
	assert(endp_vptr);
	assert(endp_vptr->load);
	assert(endp);

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);

	if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
		return -1;

	if (!endp)
		return 0;
	return endp_vptr->load(endp, (const struct sockaddr *)&addr, addrlen);
}

ssize_t
io_sock_fd_recvmsg(SOCKET fd, const struct io_buf *buf, int bufcnt, int *flags,
		const struct io_endp_vtbl *endp_vptr, struct io_endp *endp,
		int timeout)
{
	assert(!endp || endp_vptr);
	assert(!endp || endp_vptr->load);

#if _WIN32
	DWORD dwFlags = 0;
#else
	int dwFlags = 0;
#endif
	if (flags) {
		if (*flags & IO_MSG_OOB)
			dwFlags |= MSG_OOB;
		if (*flags & IO_MSG_PEEK)
			dwFlags |= MSG_PEEK;
	}

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);

#if _WIN32
	ssize_t result = io_wsa_recvfrom(fd, (LPWSABUF)buf, bufcnt, &dwFlags,
			endp ? (struct sockaddr *)&addr : NULL,
			endp ? &addrlen : NULL, timeout);
#else
	// clang-format off
	struct msghdr msg = {
		.msg_name = endp ? (struct sockaddr *)&addr : NULL,
		.msg_namelen = endp ? addrlen : 0,
		.msg_iov = (struct iovec *)buf,
		.msg_iovlen = bufcnt
	};
	// clang-format on
	ssize_t result = io_fd_recvmsg(fd, &msg, dwFlags, timeout);
	addrlen = msg.msg_namelen;
#endif

	if (result < 0)
		return -1;

	if (flags) {
		*flags = 0;
#ifdef MSG_EOR
		if (dwFlags & MSG_EOR)
			*flags |= IO_MSG_EOR;
#endif
		if (dwFlags & MSG_OOB)
			*flags |= IO_MSG_OOB;
#ifdef MSG_TRUNC
		if (dwFlags & MSG_TRUNC)
			*flags |= IO_MSG_TRUNC;
#endif
	}

	if (endp)
		endp_vptr->load(endp, (const struct sockaddr *)&addr, addrlen);

	return result;
}

ssize_t
io_sock_fd_sendmsg(SOCKET fd, const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int timeout)
{
	assert(!endp || endp_vptr);
	assert(!endp || endp_vptr->store);

#if _WIN32
	DWORD dwFlags = 0;
#else
	int dwFlags = 0;
#endif
	if (flags & IO_MSG_DONTROUTE)
		dwFlags |= MSG_DONTROUTE;
#ifdef MSG_EOR
	if (flags & IO_MSG_EOR)
		dwFlags |= MSG_EOR;
#endif
	if (flags & IO_MSG_OOB)
		dwFlags |= MSG_OOB;

	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	socklen_t addrlen = sizeof(addr);
	// clang-format off
	if (endp && endp_vptr->store(endp, (struct sockaddr *)&addr, &addrlen)
			== -1)
		// clang-format on
		return -1;

#if _WIN32
	return io_wsa_sendto(fd, (LPWSABUF)buf, bufcnt, dwFlags,
			endp ? (const SOCKADDR *)&addr : NULL,
			endp ? addrlen : 0, timeout);
#else
	// clang-format off
	struct msghdr msg = {
		.msg_name = endp ? (struct sockaddr *)&addr : NULL,
		.msg_namelen = endp ? addrlen : 0,
		.msg_iov = (struct iovec *)buf,
		.msg_iovlen = bufcnt
	};
	// clang-format on
	return io_fd_sendmsg(fd, &msg, dwFlags, timeout);
#endif
}

int
io_sock_fd_get_error(SOCKET fd)
{
	int optval = 0;
	int iError = WSAGetLastError();
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		optval = WSAGetLastError();
	WSASetLastError(iError);
	return optval;
}

int
io_sock_fd_get_nread(SOCKET fd)
{
#if _WIN32 || (LELY_HAVE_IOCTL && defined(FIONREAD))
#if _WIN32
	u_long optval = 0;
#else
	int optval = 0;
#endif
	int iError = WSAGetLastError();
	if (!ioctlsocket(fd, FIONREAD, &optval))
		return optval;
	WSASetLastError(iError);
	return 0;
#else
	(void)fd;
	return 0;
#endif
}

int
io_sock_fd_get_dontroute(SOCKET fd)
{
	int optval = 0;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_DONTROUTE, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

int
io_sock_fd_set_dontroute(SOCKET fd, int optval)
{
	// clang-format off
	return !setsockopt(fd, SOL_SOCKET, SO_DONTROUTE, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

int
io_sock_fd_get_rcvbuf(SOCKET fd)
{
	int optval = 0;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

int
io_sock_fd_set_rcvbuf(SOCKET fd, int optval)
{
	// clang-format off
	return !setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

int
io_sock_fd_get_sndbuf(SOCKET fd)
{
	int optval = 0;
	// clang-format off
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&optval,
			&(socklen_t){ sizeof(optval) }) == SOCKET_ERROR)
		// clang-format on
		return -1;
	return optval;
}

int
io_sock_fd_set_sndbuf(SOCKET fd, int optval)
{
	// clang-format off
	return !setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&optval,
			sizeof(optval)) ? 0 : -1;
	// clang-format on
}

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)
