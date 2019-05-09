/**@file
 * This header file is part of the I/O library; it contains the system UDP
 * socket declarations.
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

#ifndef LELY_IO2_SYS_UDP_H_
#define LELY_IO2_SYS_UDP_H_

#include <lely/io2/sys/io.h>
#include <lely/io2/udp.h>

#if _WIN32
#include <winsock2.h>
#endif

/// The native handle or file descriptor type of a UDP socket.
#if _WIN32
typedef SOCKET io_udp_handle_t;
#else
typedef int io_udp_handle_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *io_udp_alloc(void);
void io_udp_free(void *ptr);
io_udp_t *io_udp_init(io_udp_t *udp, io_poll_t *poll, ev_exec_t *exec);
void io_udp_fini(io_udp_t *udp);

/**
 * Creates a new UDP socket.
 *
 * @param poll a pointer to the I/O polling instance used to monitor socket
 *             events. If NULL, I/O operations MAY cause the event loop to
 *             block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new UDP socket, or NULL on error. In the latter case,
 * the error number can be obtained with get_errc().
 */
io_udp_t *io_udp_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a UDP socket. @see io_udp_create()
void io_udp_destroy(io_udp_t *udp);

/**
 * Returns the native UDP socket handle or file descriptor, or `INVALID_SOCKET`
 * or -1 if the socket is closed.
 */
io_udp_handle_t io_udp_get_handle(const io_udp_t *udp);

/**
 * Assigns an existing handle or file descriptor to a UDP socket.
 *
 * If the socket was already open, it is first closed as if by io_sock_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
int io_udp_assign(io_udp_t *udp, io_udp_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a UDP socket. Any
 * pending send or receive operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_SOCKET` or -1 if the socket
 * was closed.
 *
 * @post io_sock_is_open() returns 0.
 */
io_udp_handle_t io_udp_release(io_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SYS_UDP_H_
