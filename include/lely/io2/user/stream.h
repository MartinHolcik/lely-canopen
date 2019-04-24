/**@file
 * This header file is part of the I/O library; it contains the user-defined
 * stream declarations.
 *
 * The user-defined stream is a passive stream; it does not actively read data,
 * but requires the user to notify it of input with io_user_stream_on_read(). A
 * user-defined callback function is invoked when output data needs to be
 * written.
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

#ifndef LELY_IO2_USER_STREAM_H_
#define LELY_IO2_USER_STREAM_H_

#include <lely/io2/stream.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The type of function invoked by a user-defined stream when output data needs
 * to be written.
 *
 * @param buf    a pointer to the bytes to be written.
 * @param nbytes the number of bytes to write.
 * @param arg    the user-specific value submitted to io_user_stream_create().
 *
 * @returns 0 on success, or -1 on error. In the latter case, implementations
 * SHOULD set the error number with set_errc() or set_errnum().
 */
typedef int io_user_stream_write_t(const void *buf, size_t nbytes, void *arg);

void *io_user_stream_alloc(void);
void io_user_stream_free(void *ptr);
io_stream_t *io_user_stream_init(io_stream_t *stream, io_ctx_t *ctx,
		ev_exec_t *exec, size_t rxlen, io_user_stream_write_t *func,
		void *arg);
void io_user_stream_fini(io_stream_t *stream);

/**
 * Creates a new user-defined stream.
 *
 * @param ctx   a pointer to the I/O context with which the stream should be
 *              registered.
 * @param exec  a pointer to the executor used to execute asynchronous tasks.
 * @param rxlen the receive queue length (in bytes) of the stream. If
 *              <b>rxlen</b> is 0, the default value #LELY_IO_USER_STREAM_RXLEN
 *              is used.
 * @param func  a pointer to the function to be invoked when output data needs
 *              to be written (can be NULL).
 * @param arg   the user-specific value to be passed as the second argument to
 *              <b>func</b>.
 *
 * @returns a pointer to a new stream, or NULL on error. In the latter case,
 * the error number can be obtained with get_errc().
 */
io_stream_t *io_user_stream_create(io_ctx_t *ctx, ev_exec_t *exec, size_t rxlen,
		io_user_stream_write_t *func, void *arg);

/// Destroys a user-defined stream. @see io_user_stream_create()
void io_user_stream_destroy(io_stream_t *stream);

/**
 * Processes input data and submits the completion task of the first pending
 * read operation, if any, for execution. If the number of bytes is 0,
 * end-of-file is signaled to pending read operations and subsequent calls to
 * this function will have no effect.
 *
 * @param stream a pointer to a user-defined stream.
 * @param buf    a pointer to the input data (can be NULL if <b>nbytes</b> is
 *               0).
 * @param nbytes the number of bytes at <b>buf</b>.
 *
 * @returns 1 if a pending read operation was completed, and 0 if not.
 */
int io_user_stream_on_read(io_stream_t *stream, const void *buf, size_t nbytes);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_USER_STREAM_H_
