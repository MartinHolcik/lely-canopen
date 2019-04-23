/**@file
 * This file is part of the I/O library; it exposes the abstract stream socket
 * server functions.
 *
 * @see lely/io2/sock_stream_srv.h
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
#define LELY_IO_SOCK_STREAM_SRV_INLINE extern inline
#include <lely/io2/sock_stream_srv.h>
#include <lely/util/util.h>

#include <assert.h>

struct io_sock_stream_srv_async_accept {
	ev_promise_t *promise;
	struct io_sock_stream_srv_accept accept;
};

static void io_sock_stream_srv_async_accept_func(struct ev_task *task);

ev_future_t *
io_sock_stream_srv_async_accept(io_sock_stream_srv_t *srv, ev_exec_t *exec,
		io_sock_stream_t *sock, struct io_endp *endp,
		struct io_sock_stream_srv_accept **paccept)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_srv_async_accept), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_srv_async_accept *async_accept =
			ev_promise_data(promise);
	async_accept->promise = promise;
	async_accept->accept = (struct io_sock_stream_srv_accept)
			IO_SOCK_STREAM_SRV_ACCEPT_INIT(sock, endp, exec,
					&io_sock_stream_srv_async_accept_func);

	io_sock_stream_srv_submit_accept(srv, &async_accept->accept);

	if (paccept)
		*paccept = &async_accept->accept;

	return ev_promise_get_future(promise);
}

struct io_sock_stream_srv_accept *
io_sock_stream_srv_accept_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_stream_srv_accept, task)
			: NULL;
	// clang-format on
}

static void
io_sock_stream_srv_async_accept_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_srv_accept *accept =
			io_sock_stream_srv_accept_from_task(task);
	struct io_sock_stream_srv_async_accept *async_accept = structof(
			accept, struct io_sock_stream_srv_async_accept, accept);

	ev_promise_set(async_accept->promise, &accept->errc);
	ev_promise_release(async_accept->promise);
}
