/**@file
 * This file is part of the I/O library; it exposes the abstract datagram socket
 * functions.
 *
 * @see lely/io2/sock_dgram.h
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
#define LELY_IO_SOCK_DGRAM_INLINE extern inline
#include <lely/io2/sock_dgram.h>
#include <lely/util/util.h>

#include <assert.h>

struct io_sock_dgram_async_recvmsg {
	ev_promise_t *promise;
	struct io_sock_dgram_recvmsg recvmsg;
	int *flags;
};

static void io_sock_dgram_async_recvmsg_func(struct ev_task *task);

struct io_sock_dgram_async_recvfrom {
	ev_promise_t *promise;
	struct io_sock_dgram_recvfrom recvfrom;
	int *flags;
};

static void io_sock_dgram_async_recvfrom_func(struct ev_task *task);

struct io_sock_dgram_async_sendmsg {
	ev_promise_t *promise;
	struct io_sock_dgram_sendmsg sendmsg;
};

static void io_sock_dgram_async_sendmsg_func(struct ev_task *task);

struct io_sock_dgram_async_sendto {
	ev_promise_t *promise;
	struct io_sock_dgram_sendto sendto;
};

static void io_sock_dgram_async_sendto_func(struct ev_task *task);

ev_future_t *
io_sock_dgram_async_recvmsg(io_sock_dgram_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_endp *endp, struct io_sock_dgram_recvmsg **precvmsg)
{
	assert(flags);

	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_dgram_async_recvmsg), NULL);
	if (!promise)
		return NULL;

	struct io_sock_dgram_async_recvmsg *async_recvmsg =
			ev_promise_data(promise);
	async_recvmsg->promise = promise;
	async_recvmsg->recvmsg = (struct io_sock_dgram_recvmsg)
			IO_SOCK_DGRAM_RECVMSG_INIT(buf, bufcnt, *flags, endp,
					exec,
					&io_sock_dgram_async_recvmsg_func);
	async_recvmsg->flags = flags;

	io_sock_dgram_submit_recvmsg(sock, &async_recvmsg->recvmsg);

	if (precvmsg)
		*precvmsg = &async_recvmsg->recvmsg;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_dgram_async_recvfrom(io_sock_dgram_t *sock, ev_exec_t *exec, void *buf,
		size_t nbytes, int *flags, struct io_endp *endp,
		struct io_sock_dgram_recvfrom **precvfrom)
{
	assert(flags);

	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_dgram_async_recvfrom), NULL);
	if (!promise)
		return NULL;

	struct io_sock_dgram_async_recvfrom *async_recvfrom =
			ev_promise_data(promise);
	async_recvfrom->promise = promise;
	async_recvfrom->recvfrom = (struct io_sock_dgram_recvfrom)
			IO_SOCK_DGRAM_RECVFROM_INIT(&async_recvfrom->recvfrom,
					buf, nbytes, *flags, endp, exec,
					&io_sock_dgram_async_recvfrom_func);
	async_recvfrom->flags = flags;

	io_sock_dgram_submit_recvfrom(sock, &async_recvfrom->recvfrom);

	if (precvfrom)
		*precvfrom = &async_recvfrom->recvfrom;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_dgram_async_sendmsg(io_sock_dgram_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendmsg **psendmsg)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_dgram_async_sendmsg), NULL);
	if (!promise)
		return NULL;

	struct io_sock_dgram_async_sendmsg *async_sendmsg =
			ev_promise_data(promise);
	async_sendmsg->promise = promise;
	async_sendmsg->sendmsg = (struct io_sock_dgram_sendmsg)
			IO_SOCK_DGRAM_SENDMSG_INIT(buf, bufcnt, flags, endp,
					exec,
					&io_sock_dgram_async_sendmsg_func);

	io_sock_dgram_submit_sendmsg(sock, &async_sendmsg->sendmsg);

	if (psendmsg)
		*psendmsg = &async_sendmsg->sendmsg;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_dgram_async_sendto(io_sock_dgram_t *sock, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		const struct io_endp *endp,
		struct io_sock_dgram_sendto **psendto)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_dgram_async_sendto), NULL);
	if (!promise)
		return NULL;

	struct io_sock_dgram_async_sendto *async_sendto =
			ev_promise_data(promise);
	async_sendto->promise = promise;
	async_sendto->sendto =
			(struct io_sock_dgram_sendto)IO_SOCK_DGRAM_SENDTO_INIT(
					&async_sendto->sendto, buf, nbytes,
					flags, endp, exec,
					&io_sock_dgram_async_sendto_func);

	io_sock_dgram_submit_sendto(sock, &async_sendto->sendto);

	if (psendto)
		*psendto = &async_sendto->sendto;

	return ev_promise_get_future(promise);
}

struct io_sock_dgram_recvmsg *
io_sock_dgram_recvmsg_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_dgram_recvmsg, task)
			: NULL;
	// clang-format on
}

struct io_sock_dgram_recvfrom *
io_sock_dgram_recvfrom_from_task(struct ev_task *task)
{
	struct io_sock_dgram_recvmsg *recvmsg =
			io_sock_dgram_recvmsg_from_task(task);
	// clang-format off
	return recvmsg ? structof(recvmsg, struct io_sock_dgram_recvfrom, recvmsg)
			: NULL;
	// clang-format on
}

struct io_sock_dgram_sendmsg *
io_sock_dgram_sendmsg_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_dgram_sendmsg, task)
			: NULL;
	// clang-format on
}

struct io_sock_dgram_sendto *
io_sock_dgram_sendto_from_task(struct ev_task *task)
{
	struct io_sock_dgram_sendmsg *sendmsg =
			io_sock_dgram_sendmsg_from_task(task);
	// clang-format off
	return sendmsg ? structof(sendmsg, struct io_sock_dgram_sendto, sendmsg)
			: NULL;
	// clang-format on
}

static void
io_sock_dgram_async_recvmsg_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_recvmsg *recvmsg =
			io_sock_dgram_recvmsg_from_task(task);
	struct io_sock_dgram_async_recvmsg *async_recvmsg = structof(
			recvmsg, struct io_sock_dgram_async_recvmsg, recvmsg);

	*async_recvmsg->flags = recvmsg->flags;
	ev_promise_set(async_recvmsg->promise, &recvmsg->r);
	ev_promise_release(async_recvmsg->promise);
}

static void
io_sock_dgram_async_recvfrom_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_recvfrom *recvfrom =
			io_sock_dgram_recvfrom_from_task(task);
	struct io_sock_dgram_async_recvfrom *async_recvfrom = structof(recvfrom,
			struct io_sock_dgram_async_recvfrom, recvfrom);

	*async_recvfrom->flags = recvfrom->recvmsg.flags;
	ev_promise_set(async_recvfrom->promise, &recvfrom->recvmsg.r);
	ev_promise_release(async_recvfrom->promise);
}

static void
io_sock_dgram_async_sendmsg_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_sendmsg *sendmsg =
			io_sock_dgram_sendmsg_from_task(task);
	struct io_sock_dgram_async_sendmsg *async_sendmsg = structof(
			sendmsg, struct io_sock_dgram_async_sendmsg, sendmsg);

	ev_promise_set(async_sendmsg->promise, &sendmsg->r);
	ev_promise_release(async_sendmsg->promise);
}

static void
io_sock_dgram_async_sendto_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_dgram_sendto *sendto =
			io_sock_dgram_sendto_from_task(task);
	struct io_sock_dgram_async_sendto *async_sendto = structof(
			sendto, struct io_sock_dgram_async_sendto, sendto);

	ev_promise_set(async_sendto->promise, &sendto->sendmsg.r);
	ev_promise_release(async_sendto->promise);
}
