/**@file
 * This file is part of the I/O library; it exposes the abstract socket
 * functions.
 *
 * @see lely/io2/sock.h
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

#include "io2.h"
#define LELY_IO_SOCK_INLINE extern inline
#include <lely/io2/sock.h>
#include <lely/util/util.h>

#include <assert.h>

struct io_sock_async_wait {
	ev_promise_t *promise;
	struct io_sock_wait wait;
	int *events;
};

static void io_sock_async_wait_func(struct ev_task *task);

ev_future_t *
io_sock_async_wait(io_sock_t *sock, ev_exec_t *exec, int *events,
		struct io_sock_wait **pwait)
{
	assert(events);

	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_async_wait), NULL);
	if (!promise)
		return NULL;

	struct io_sock_async_wait *async_wait = ev_promise_data(promise);
	async_wait->promise = promise;
	async_wait->wait = (struct io_sock_wait)IO_SOCK_WAIT_INIT(
			*events, exec, &io_sock_async_wait_func);
	async_wait->events = events;

	io_sock_submit_wait(sock, &async_wait->wait);

	if (pwait)
		*pwait = &async_wait->wait;

	return ev_promise_get_future(promise);
}

struct io_sock_wait *
io_sock_wait_from_task(struct ev_task *task)
{
	return task ? structof(task, struct io_sock_wait, task) : NULL;
}

static void
io_sock_async_wait_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_wait *wait = io_sock_wait_from_task(task);
	struct io_sock_async_wait *async_wait =
			structof(wait, struct io_sock_async_wait, wait);

	*async_wait->events = wait->events;
	ev_promise_set(async_wait->promise, &wait->errc);
	ev_promise_release(async_wait->promise);
}
