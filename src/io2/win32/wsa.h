/**@file
 * This is the internal header file of the Windows Sockets API (WSA) functions.
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

#ifndef LELY_IO2_INTERN_WIN32_WSA_H_
#define LELY_IO2_INTERN_WIN32_WSA_H_

#include "io.h"

#if _WIN32

#include <lely/libc/sys/types.h>

#include <mswsock.h>
#include <winsock2.h>

#ifndef WSA_FLAG_NO_HANDLE_INHERIT
#define WSA_FLAG_NO_HANDLE_INHERIT 0x80
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// Returns a pointer to the AcceptEx() extension function.
LPFN_ACCEPTEX io_wsa_get_acceptex(SOCKET s);

/// Returns a pointer to the ConnectEx() extension function.
LPFN_CONNECTEX io_wsa_get_connectex(SOCKET s);

/**
 * Disables blocking mode for the specified socket.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained from `WSAetLastError()`.
 */
int io_wsa_set_nonblock(SOCKET s);

/**
 * Waits for one or more of the I/O events in *<b>events</b> to occur as if by
 * `WSAPoll()`. On succes, the reported events are stored in *<b>events</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained from `errno`.
 */
int io_wsa_wait(SOCKET s, int *events, int timeout);

/**
 * Equivalent to `socket(af, type, protocol)`, except that the resulting socket
 * is non-blocking and has the `WSA_FLAG_NO_HANDLE_INHERIT` flag set.
 */
SOCKET io_wsa_socket(int af, int type, int protocol);

/**
 * Equivalent to `accept(s, addr, addrlen)`, except that if <b>s</b> is
 * non-blocking and <b>timeout</b> is non-negative, this function will block
 * until a pending connection is accepted or <b>timeout</b> milliseconds have
 * elapsed. On success, the accepted socket has the `WSA_FLAG_NO_HANDLE_INHERIT`
 * flag set.
 */
SOCKET io_wsa_accept(SOCKET s, SOCKADDR *addr, int *addrlen, int timeout);

/**
 * Equivalent to `connect(s, name, namelen)`, except that if <b>s</b> is
 * non-blocking and <b>dontwait</b> is 0, this function behaves as if <b>s</b>
 * is blocking.
 */
int io_wsa_connect(SOCKET s, const SOCKADDR *name, int namelen, int dontwait);

/**
 * Equivalent to `WSARecvFrom()`, except that this function returns the number
 * of bytes received on success, or -1 on error, and if <b>s</b> is non-blocking
 * and <b>timeout</b> is non-negative, this function behaves as if <b>s</b> is
 * blocking and the `SO_RCVTIMEO` option is set with <b>timeout</b>
 * milliseconds.
 */
ssize_t io_wsa_recvfrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
		LPDWORD lpFlags, SOCKADDR *lpFrom, LPINT lpFromlen,
		int timeout);

/**
 * Equivalent to `WSASendTo()`, except that this function returns the number of
 * bytes sent on success, or -1 on error, and if <b>s</b> is non-blocking and
 * <b>timeout</b> is non-negative, this function behaves as if <b>s</b> is
 * blocking and the `SO_SNDTIMEO` option is set with <b>timeout</b>
 * milliseconds.
 */
ssize_t io_wsa_sendto(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
		DWORD dwFlags, const SOCKADDR *lpTo, int iTolen, int timeout);

/// Returns the base service provider handle for the socket.
SOCKET io_wsa_base_handle(SOCKET s);

#ifdef __cplusplus
}
#endif

#endif // _WIN32

#endif // !LELY_IO2_INTERN_WIN32_WSA_H_
