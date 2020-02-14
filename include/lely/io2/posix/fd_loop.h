/**@file
 * This header file is part of the event library; it contains the file
 * descriptor event loop declarations.
 *
 * @copyright 2020 Lely Industries N.V.
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

#ifndef LELY_IO2_POSIX_FD_LOOP_H_
#define LELY_IO2_POSIX_FD_LOOP_H_

#include <lely/ev/exec.h>
#include <lely/io2/posix/poll.h>

/// A file descriptor event loop.
typedef struct io_fd_loop io_fd_loop_t;

#ifdef __cplusplus
extern "C" {
#endif

void *io_fd_loop_alloc(void);
void io_fd_loop_free(void *ptr);
io_fd_loop_t *io_fd_loop_init(io_fd_loop_t *loop, io_poll_t *poll);
void io_fd_loop_fini(io_fd_loop_t *loop);

/**
 * Creates a new file descriptor event loop.
 *
 * @param poll a pointer to the I/O polling instance used to monitor the event
 *             loop.
 *
 * @returns a pointer to the new event loop, or NULL on error. In the latter
 * case, the error number can be obtained with get_errc().
 */
io_fd_loop_t *io_fd_loop_create(io_poll_t *poll);

/// Destroys a file descriptor event loop. @see io_fd_loop_create()
void io_fd_loop_destroy(io_fd_loop_t *loop);

/// Returns a pointer to the polling instance used by the event loop.
ev_poll_t *io_fd_loop_get_poll(const io_fd_loop_t *loop);

/// Returns a pointer to the executor corresponding to the event loop.
ev_exec_t *io_fd_loop_get_exec(const io_fd_loop_t *loop);

/// Returns the file descriptor corresponding to the event loop.
int io_fd_loop_get_fd(const io_fd_loop_t *loop);

/**
 * Stops the file descriptor event loop. Subsequent calls to io_fd_loop_run()
 * and io_fd_loop_run_one() will return 0 immediately.
 *
 * @post io_fd_loop_stopped() returns 1.
 */
void io_fd_loop_stop(io_fd_loop_t *loop);

/// Returns 1 if the file descriptor event loop is stopped, and 0 if not.
int io_fd_loop_stopped(io_fd_loop_t *loop);

/// Restarts a file descriptor event loop. @post io_fd_loop_stopped() returns 0.
void io_fd_loop_restart(io_fd_loop_t *loop);

/**
 * Equivalent to
 * ```{.c}
 * size_t n = 0;
 * while (io_fd_loop_run_one(loop))
 *         n += n < SIZE_MAX;
 * return n;
 * ```
 */
size_t io_fd_loop_run(io_fd_loop_t *loop);


size_t io_fd_loop_run_one(io_fd_loop_t *loop);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_POSIX_FD_LOOP_H_
