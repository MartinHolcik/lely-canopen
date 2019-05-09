/**@file
 * This header file is part of the I/O library; it contains the system Bluetooth
 * RFCOMM socket declarations.
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

#ifndef LELY_IO2_SYS_RFCOMM_H_
#define LELY_IO2_SYS_RFCOMM_H_

#include <lely/io2/rfcomm.h>
#include <lely/io2/sys/io.h>

#if _WIN32
#include <winsock2.h>
#endif

/**
 * The native handle or file descriptor type of a Bluetooth RFCOMM server or
 * socket.
 */
#if _WIN32
typedef SOCKET io_rfcomm_handle_t;
#else
typedef int io_rfcomm_handle_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *io_rfcomm_srv_alloc(void);
void io_rfcomm_srv_free(void *ptr);
io_rfcomm_srv_t *io_rfcomm_srv_init(
		io_rfcomm_srv_t *rfcomm, io_poll_t *poll, ev_exec_t *exec);
void io_rfcomm_srv_fini(io_rfcomm_srv_t *rfcomm);

/**
 * Creates a new Bluetooth RFCOMM server.
 *
 * @param poll a pointer to the I/O polling instance used to monitor socket
 *             events. If NULL, I/O operations MAY cause the event loop to
 *             block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new RFCOMM server, or NULL on error. In the latter
 * case, the error number can be obtained with get_errc().
 */
io_rfcomm_srv_t *io_rfcomm_srv_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a Bluetooth RFCOMM server. @see io_rfcomm_srv_create()
void io_rfcomm_srv_destroy(io_rfcomm_srv_t *rfcomm);

/**
 * Returns the native Bluetooth RFCOMM server handle or file descriptor, or
 * `INVALID_SOCKET` or -1 if the socket is closed.
 */
io_rfcomm_handle_t io_rfcomm_srv_get_handle(const io_rfcomm_srv_t *rfcomm);

/**
 * Assigns an existing handle or file descriptor to a Bluetooth RFCOMM server.
 *
 * If the socket was already open, it is first closed as if by io_sock_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
int io_rfcomm_srv_assign(io_rfcomm_srv_t *rfcomm, io_rfcomm_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a Bluetooth RFCOMM
 * server. Any pending accept operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_SOCKET` or -1 if the socket
 * was closed.
 *
 * @post io_sock_is_open() returns 0.
 */
io_rfcomm_handle_t io_rfcomm_srv_release(io_rfcomm_srv_t *rfcomm);

void *io_rfcomm_alloc(void);
void io_rfcomm_free(void *ptr);
io_rfcomm_t *io_rfcomm_init(
		io_rfcomm_t *rfcomm, io_poll_t *poll, ev_exec_t *exec);
void io_rfcomm_fini(io_rfcomm_t *rfcomm);

/**
 * Creates a new Bluetooth RFCOMM socket.
 *
 * @param poll a pointer to the I/O polling instance used to monitor socket
 *             events. If NULL, I/O operations MAY cause the event loop to
 *             block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new RFCOMM socket, or NULL on error. In the latter
 * case, the error number can be obtained with get_errc().
 */
io_rfcomm_t *io_rfcomm_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a Bluetooth RFCOMM socket. @see io_rfcomm_create()
void io_rfcomm_destroy(io_rfcomm_t *rfcomm);

/**
 * Returns the native Bluetooth RFCOMM socket handle or file descriptor, or
 * `INVALID_SOCKET` or -1 if the socket is closed.
 */
io_rfcomm_handle_t io_rfcomm_get_handle(const io_rfcomm_t *rfcomm);

/**
 * Assigns an existing handle or file descriptor to a Bluetooth RFCOMM socket.
 *
 * If the socket was already open, it is first closed as if by io_sock_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_sock_is_open() returns 1.
 */
int io_rfcomm_assign(io_rfcomm_t *rfcomm, io_rfcomm_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a Bluetooth RFCOMM
 * socket. Any pending connect, send or receive operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_SOCKET` or -1 if the socket
 * was closed.
 *
 * @post io_sock_is_open() returns 0.
 */
io_rfcomm_handle_t io_rfcomm_release(io_rfcomm_t *rfcomm);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SYS_RFCOMM_H_
