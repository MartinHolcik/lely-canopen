/**@file
 * This header file is part of the I/O library; it contains the system serial
 * port declarations.
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

#ifndef LELY_IO2_SYS_SERIAL_H_
#define LELY_IO2_SYS_SERIAL_H_

#include <lely/io2/serial.h>
#include <lely/io2/sys/io.h>

/// The native handle or file descriptor type of a serial port.
#if _WIN32
typedef HANDLE io_serial_handle_t;
#else
typedef int io_serial_handle_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

void *io_serial_alloc(void);
void io_serial_free(void *ptr);
io_serial_t *io_serial_init(
		io_serial_t *serial, io_poll_t *poll, ev_exec_t *exec);
void io_serial_fini(io_serial_t *serial);

/**
 * Creates a new serial port.
 *
 * @param poll a pointer to the I/O polling instance used to monitor I/O events.
 *             If NULL, I/O operations MAY cause the event loop to block.
 * @param exec a pointer to the executor used to execute asynchronous tasks.
 *
 * @returns a pointer to a new serial port, or NULL on error. In the latter
 * case, the error number can be obtained with get_errc().
 */
io_serial_t *io_serial_create(io_poll_t *poll, ev_exec_t *exec);

/// Destroys a serial port. @see io_serial_create()
void io_serial_destroy(io_serial_t *serial);

/**
 * Returns the native serial port handle or file descriptor, or
 * `INVALID_HANDLE_VALUE` or -1 if the port is closed.
 */
io_serial_handle_t io_serial_get_handle(const io_serial_t *serial);

/**
 * Opens a serial port. If the port was already open, it is first closed as if
 * by io_serial_close().
 *
 * @param serial   a pointer to a serial port.
 * @param filename a pointer to the (platform-specific) device name.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_serial_is_open() returns 1.
 */
int io_serial_open(io_serial_t *serial, const char *filename);

/**
 * Assigns an existing handle or file descriptor to a serial port.
 *
 * If the port was already open, it is first closed as if by io_serial_close().
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @post on success, io_serial_is_open() returns 1.
 */
int io_serial_assign(io_serial_t *serial, io_serial_handle_t fd);

/**
 * Dissociates and returns the handle or file descriptor from a serial port. Any
 * pending send or receive operations are canceled.
 *
 * @returns a handle or file descriptor, or `INVALID_HANDLE_VALUE` or -1 if the
 * port was closed.
 *
 * @post io_serial_is_open() returns 0.
 */
io_serial_handle_t io_serial_release(io_serial_t *serial);

/// Returns 1 if the serial port is open and 0 if not.
int io_serial_is_open(const io_serial_t *serial);

/**
 * Closes the serial port if it is open. Any pending read or write operations
 * are canceled.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc(). Note that, on POSIX platforms, the port is
 * closed even when this function reports an error.
 *
 * @post io_serial_is_open() returns 0.
 */
int io_serial_close(io_serial_t *serial);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_SYS_SERIAL_H_
