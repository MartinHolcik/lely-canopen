/**@file
 * This header file is part of the I/O library; it contains the system TCP
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

#ifndef LELY_IO2_SYS_TCP_H_
#define LELY_IO2_SYS_TCP_H_

#include <lely/io2/sys/io.h>
#include <lely/io2/tcp.h>

#if _WIN32
#include <winsock2.h>
#endif

/// The native handle or file descriptor type of a TCP server or socket.
#if _WIN32
typedef SOCKET io_tcp_handle_t;
#else
typedef int io_tcp_handle_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *io_tcp_srv_alloc(void);
void io_tcp_srv_free(void *ptr);
io_tcp_srv_t *io_tcp_srv_init(
		io_tcp_srv_t *tcp, io_poll_t *poll, ev_exec_t *exec);
void io_tcp_srv_fini(io_tcp_srv_t *tcp);

/**
 * Creates a new TCP server.
 *
 * @param poll a pointer to the I/O polling instance used to monitor socket
 *             events. If NULL, I/O operations MAY cause the event loop to
 *             block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new TCP server, or NULL on error. In the latter case,
 * the error number can be obtained with get_errc().
 */
io_tcp_srv_t *io_tcp_srv_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a TCP server. @see io_tcp_srv_create()
void io_tcp_srv_destroy(io_tcp_srv_t *tcp);

/**
 * Returns the native TCP server handle or file descriptor, or `INVALID_SOCKET`
 * or -1 if the socket is closed.
 */
io_tcp_handle_t io_tcp_srv_get_handle(const io_tcp_srv_t *tcp);

/**
 * Assigns an existing handle or file descriptor to a TCP server.
 *
 * If the socket was already open, it is first closed as if by io_sock_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
int io_tcp_srv_assign(io_tcp_srv_t *tcp, io_tcp_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a TCP server. Any
 * pending accept operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_SOCKET` or -1 if the socket
 * was closed.
 *
 * @post io_sock_is_open() returns 0.
 */
io_tcp_handle_t io_tcp_srv_release(io_tcp_srv_t *tcp);

void *io_tcp_alloc(void);
void io_tcp_free(void *ptr);
io_tcp_t *io_tcp_init(io_tcp_t *tcp, io_poll_t *poll, ev_exec_t *exec);
void io_tcp_fini(io_tcp_t *tcp);

/**
 * Creates a new TCP socket.
 *
 * @param poll a pointer to the I/O polling instance used to monitor socket
 *             events. If NULL, I/O operations MAY cause the event loop to
 *             block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new TCP socket, or NULL on error. In the latter case,
 * the error number can be obtained with get_errc().
 */
io_tcp_t *io_tcp_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a TCP socket. @see io_tcp_create()
void io_tcp_destroy(io_tcp_t *tcp);

/**
 * Returns the native TCP socket handle or file descriptor, or `INVALID_SOCKET`
 * or -1 if the socket is closed.
 */
io_tcp_handle_t io_tcp_get_handle(const io_tcp_t *tcp);

/**
 * Assigns an existing handle or file descriptor to a TCP socket.
 *
 * If the socket was already open, it is first closed as if by io_sock_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
int io_tcp_assign(io_tcp_t *tcp, io_tcp_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a TCP socket. Any
 * pending connect, send or receive operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_SOCKET` or -1 if the socket
 * was closed.
 *
 * @post io_sock_is_open() returns 0.
 */
io_tcp_handle_t io_tcp_release(io_tcp_t *tcp);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SYS_TCP_H_
