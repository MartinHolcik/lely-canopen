/**@file
 * This is the internal header file of the socket declarations.
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

#ifndef LELY_IO2_INTERN_SYS_SOCK_H_
#define LELY_IO2_INTERN_SYS_SOCK_H_

#include "../io2.h"

#if _WIN32 || (defined(_POSIX_C_SOURCE) && !defined(__NEWLIB__))

#include <lely/io2/buf.h>
#include <lely/io2/endp.h>

#if _POSIX_C_SOURCE
#include <errno.h>
#include <sys/socket.h>
#endif

#if _WIN32
#include <winsock2.h>
#endif

#if !_WIN32

typedef int SOCKET;

#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR

#define ERROR_OPERATION_ABORTED ECANCELED

#define WSAEAGAIN EAGAIN
#define WSAEINVAL EINVAL
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEPROTONOSUPPORT EPROTONOSUPPORT
#define WSAEAFNOSUPPORT EAFNOSUPPORT
#define WSAEISCONN EISCONN
#define WSAENOTCONN ENOTCONN

#define closesocket close

#endif // !_WIN32

#ifndef WSAEAGAIN
#define WSAEAGAIN WSAEWOULDBLOCK
#endif

#if !defined(_POSIX_C_SOURCE)
typedef int socklen_t;
#endif

union io_sockaddr_storage_ {
	struct io_sockaddr_storage _io_ss;
	struct sockaddr _sa;
	struct sockaddr_storage _ss;
};

#ifdef __cplusplus
extern "C" {
#endif

struct io_endp_vtbl {
	int (*load)(struct io_endp *endp, const struct sockaddr *addr,
			socklen_t addrlen);
	int (*store)(const struct io_endp *endp, struct sockaddr *addr,
			socklen_t *addrlen);
	int (*store_any)(int family, int protocol, struct sockaddr *addr,
			socklen_t *addrlen);
};

#if !_WIN32
static inline int WSAGetLastError();
static inline void WSASetLastError(int iError);
#endif

#if _WIN32
int io_sock_fd_init(SOCKET fd, SOCKET *pbase, int *pfamily, int *pprotocol,
		int *pskip_iocp);
#endif

int io_sock_fd_bind(SOCKET fd, int family, int protocol,
		const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int reuseaddr);
int io_sock_fd_getsockname(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp);

int io_sock_fd_wait(SOCKET fd, int *events, int timeout);

SOCKET io_sock_fd_accept(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp, int timeout);

int io_sock_fd_connect(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int dontwait);
int io_sock_fd_getpeername(SOCKET fd, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp);

ssize_t io_sock_fd_recvmsg(SOCKET fd, const struct io_buf *buf, int bufcnt,
		int *flags, const struct io_endp_vtbl *endp_vptr,
		struct io_endp *endp, int timeout);
ssize_t io_sock_fd_sendmsg(SOCKET fd, const struct io_buf *buf, int bufcnt,
		int flags, const struct io_endp_vtbl *endp_vptr,
		const struct io_endp *endp, int timeout);

int io_sock_fd_get_error(SOCKET fd);

int io_sock_fd_get_nread(SOCKET fd);

int io_sock_fd_get_dontroute(SOCKET fd);
int io_sock_fd_set_dontroute(SOCKET fd, int optval);

int io_sock_fd_get_rcvbuf(SOCKET fd);
int io_sock_fd_set_rcvbuf(SOCKET fd, int optval);

int io_sock_fd_get_sndbuf(SOCKET fd);
int io_sock_fd_set_sndbuf(SOCKET fd, int optval);

#if !_WIN32

static inline int
WSAGetLastError()
{
	return errno;
}

static inline void
WSASetLastError(int iError)
{
	errno = iError;
}

#endif // !_WIN32

#ifdef __cplusplus
}
#endif

#endif // _WIN32 || (_POSIX_C_SOURCE && !__NEWLIB__)

#endif // !LELY_IO2_INTERN_SYS_SOCK_H_
