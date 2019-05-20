/**@file
 * This header file is part of the I/O library; it contains the I/O polling
 * declarations for Windows.
 *
 * The Windows implementation is based on I/O completion ports. Readiness
 * notifications for sockets are based on the (undocumented) Ancillary Function
 * Driver (AFD).
 *
 * @see lely/io2/win32/afd.h
 *
 * @copyright 2018-2019 Lely Industries N.V.
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

#ifndef LELY_IO2_WIN32_POLL_H_
#define LELY_IO2_WIN32_POLL_H_

#include <lely/ev/poll.h>
#include <lely/io2/ctx.h>
#include <lely/io2/event.h>
#include <lely/io2/sys/io.h>
#include <lely/io2/win32/afd.h>

struct io_cp;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The type of function invoked by an I/O polling instance (through
 * ev_poll_wait()) when an overlapped I/O operation completes.
 *
 * @param cp     a pointer to the I/O completion packet.
 * @param nbytes the number of bytes transfered in the operation.
 * @param errc   the error code.
 */
typedef void io_cp_func_t(struct io_cp *cp, size_t nbytes, int errc);

/**
 * An I/O completion packet. Additional data can be associated with an
 * completion packet by embedding it in a struct and using structof() from the
 * #io_cp_func_t callback fuction to obtain a pointer to the struct.
 */
struct io_cp {
	/**
	 * A pointer to the function to be invoked when the I/O operation
	 * completes.
	 */
	io_cp_func_t *func;
	/**
	 * The OVERLAPPED structure submitted to the asynchronous I/O operation.
	 */
	OVERLAPPED overlapped;
};

/// The static initializer for #io_cp.
#define IO_CP_INIT(func) \
	{ \
		(func), { 0, 0, { { 0, 0 } }, NULL } \
	}

void *io_poll_alloc(void);
void io_poll_free(void *ptr);
io_poll_t *io_poll_init(io_poll_t *poll, io_ctx_t *ctx);
void io_poll_fini(io_poll_t *poll);

/**
 * Creates a new I/O polling instance. The polling instance creates and manages
 * an I/O completion port.
 *
 * @param ctx a pointer to the I/O context with which the polling instance
 *            should be registered.
 *
 * @returns a pointer to the new polling instance, or NULL on error. In the
 * latter case, the error number can be obtained with GetLastError().
 */
io_poll_t *io_poll_create(io_ctx_t *ctx);

/// Destroys an I/O polling instance. @see io_poll_create()
void io_poll_destroy(io_poll_t *poll);

/**
 * Returns a pointer to the I/O context with which the I/O polling instance is
 * registered.
 */
io_ctx_t *io_poll_get_ctx(const io_poll_t *poll);

/**
 * Returns a pointer to the #ev_poll_t instance corresponding to the I/O polling
 * instance.
 */
ev_poll_t *io_poll_get_poll(const io_poll_t *poll);

/**
 * Registers a file handle with (the I/O completion port of) an I/O polling
 * instance. This operation cannot be undone.
 *
 * This function is implemented using `CreateIoCompletionPort()`.
 *
 * @param poll   a pointer to an I/O polling instance.
 * @param handle the file handle to be registered.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with GetLastError().
 */
int io_poll_register_handle(io_poll_t *poll, HANDLE handle);

/**
 * Posts a completion packet to the I/O completion port of an I/O polling
 * instance.
 *
 * @param poll   a pointer to an I/O polling instance.
 * @param nbytes the number of bytes reported to the #io_cp_func_t callback
 *               function.
 * @param cp     a pointer to an I/O completion packet.
 *
 * This function is implemented using `PostQueuedCompletionStatus()`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with GetLastError().
 */
int io_poll_post(io_poll_t *poll, size_t nbytes, struct io_cp *cp);

/**
 * Performs a synchronous AFD poll operation on a single socket.
 *
 * @param poll    a pointer to an I/O polling instance.
 * @param handle  the socket handle to monitor. This MUST be a base service
 *                provider handle.
 * @param events  on input, a pointer to the I/O events to be monitored (any
 *                combination of #IO_EVENT_IN, #IO_EVENT_PRI, #IO_EVENT_OUT,
 *                #IO_EVENT_ERR and #IO_EVENT_HUP). On output, *<b>events</b>
 *                contains the reported events. Note that error and disconnect
 *                events are monitored regardless of whether #IO_EVENT_ERR and
 *                #IO_EVENT_HUP are specified on input.
 * @param timeout the maximum number of milliseconds this function will block.
 *                If <b>timeout</b> is negative, this function will block
 *                indefinitely.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with GetLastError().
 */
int io_poll_afd(io_poll_t *poll, HANDLE handle, int *events, int timeout);

/**
 * Submits an AFD poll operation on one or more sockets.
 *
 * @param poll a pointer to an I/O polling instance.
 * @param info a pointer to an opaque AFD poll information struct. It is the
 *             responsibility of the caller to ensure the buffer is initialized
 *             and remains valid until the poll operation completes.
 * @param cp   a pointer to the I/O completion packet to be posted once an I/O
 *             event occurs.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with GetLastError().
 *
 * @see io_poll_cancel_afd()
 */
int io_poll_submit_afd(io_poll_t *poll, AFD_POLL_INFO *info, struct io_cp *cp);

/**
 * Cancels an AFD poll operation.
 *
 * @returns 1 if the operation was canceled and 0 if not.
 *
 * @see io_poll_submit_afd()
 */
int io_poll_cancel_afd(io_poll_t *poll, struct io_cp *cp);

/**
 * Converts the specified AFD poll events to I/O events.
 *
 * @returns any combination of #IO_EVENT_IN, #IO_EVENT_PRI, #IO_EVENT_OUT,
 * #IO_EVENT_ERR and #IO_EVENT_HUP.
 *
 * @see io_event_to_afd_poll()
 */
int io_afd_poll_to_event(ULONG Events);

/**
 * Converts the specified I/O events (any combination of #IO_EVENT_IN,
 * #IO_EVENT_PRI, #IO_EVENT_OUT, #IO_EVENT_ERR and #IO_EVENT_HUP) to AFD poll
 * events. Note that error and disconnect events are included regardless of
 * whether #IO_EVENT_ERR and #IO_EVENT_HUP are specified.
 */
ULONG io_event_to_afd_poll(int events);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_WIN32_POLL_H_
