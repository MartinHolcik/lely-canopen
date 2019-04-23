/**@file
 * This file is part of the I/O library; it exposes the abstract stream socket
 * functions.
 *
 * @see lely/io2/sock_stream.h
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
#define LELY_IO_SOCK_STREAM_INLINE extern inline
#include <lely/io2/sock_stream.h>
#include <lely/util/util.h>

#include <assert.h>

struct io_sock_stream_async_connect {
	ev_promise_t *promise;
	struct io_sock_stream_connect connect;
};

static void io_sock_stream_async_connect_func(struct ev_task *task);

struct io_sock_stream_async_recvmsg {
	ev_promise_t *promise;
	struct io_sock_stream_recvmsg recvmsg;
	int *flags;
};

static void io_sock_stream_async_recvmsg_func(struct ev_task *task);

struct io_sock_stream_async_recv {
	ev_promise_t *promise;
	struct io_sock_stream_recv recv;
	int *flags;
};

static void io_sock_stream_async_recv_func(struct ev_task *task);

struct io_sock_stream_async_sendmsg {
	ev_promise_t *promise;
	struct io_sock_stream_sendmsg sendmsg;
};

static void io_sock_stream_async_sendmsg_func(struct ev_task *task);

struct io_sock_stream_async_send {
	ev_promise_t *promise;
	struct io_sock_stream_send send;
};

static void io_sock_stream_async_send_func(struct ev_task *task);

ev_future_t *
io_sock_stream_async_connect(io_sock_stream_t *sock, ev_exec_t *exec,
		const struct io_endp *endp,
		struct io_sock_stream_connect **pconnect)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_async_connect), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_async_connect *async_connect =
			ev_promise_data(promise);
	async_connect->promise = promise;
	async_connect->connect = (struct io_sock_stream_connect)
			IO_SOCK_STREAM_CONNECT_INIT(endp, exec,
					&io_sock_stream_async_connect_func);

	io_sock_stream_submit_connect(sock, &async_connect->connect);

	if (pconnect)
		*pconnect = &async_connect->connect;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_stream_async_recvmsg(io_sock_stream_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int *flags,
		struct io_sock_stream_recvmsg **precvmsg)
{
	assert(flags);

	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_async_recvmsg), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_async_recvmsg *async_recvmsg =
			ev_promise_data(promise);
	async_recvmsg->promise = promise;
	async_recvmsg->recvmsg = (struct io_sock_stream_recvmsg)
			IO_SOCK_STREAM_RECVMSG_INIT(buf, bufcnt, *flags, exec,
					&io_sock_stream_async_recvmsg_func);
	async_recvmsg->flags = flags;

	io_sock_stream_submit_recvmsg(sock, &async_recvmsg->recvmsg);

	if (precvmsg)
		*precvmsg = &async_recvmsg->recvmsg;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_stream_async_recv(io_sock_stream_t *sock, ev_exec_t *exec, void *buf,
		size_t nbytes, int *flags, struct io_sock_stream_recv **precv)
{
	assert(flags);

	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_async_recv), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_async_recv *async_recv = ev_promise_data(promise);
	async_recv->promise = promise;
	async_recv->recv = (struct io_sock_stream_recv)IO_SOCK_STREAM_RECV_INIT(
			&async_recv->recv, buf, nbytes, *flags, exec,
			&io_sock_stream_async_recv_func);
	async_recv->flags = flags;

	io_sock_stream_submit_recv(sock, &async_recv->recv);

	if (precv)
		*precv = &async_recv->recv;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_stream_async_sendmsg(io_sock_stream_t *sock, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt, int flags,
		struct io_sock_stream_sendmsg **psendmsg)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_async_sendmsg), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_async_sendmsg *async_sendmsg =
			ev_promise_data(promise);
	async_sendmsg->promise = promise;
	async_sendmsg->sendmsg = (struct io_sock_stream_sendmsg)
			IO_SOCK_STREAM_SENDMSG_INIT(buf, bufcnt, flags, exec,
					&io_sock_stream_async_sendmsg_func);

	io_sock_stream_submit_sendmsg(sock, &async_sendmsg->sendmsg);

	if (psendmsg)
		*psendmsg = &async_sendmsg->sendmsg;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_sock_stream_async_send(io_sock_stream_t *sock, ev_exec_t *exec,
		const void *buf, size_t nbytes, int flags,
		struct io_sock_stream_send **psend)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_sock_stream_async_send), NULL);
	if (!promise)
		return NULL;

	struct io_sock_stream_async_send *async_send = ev_promise_data(promise);
	async_send->promise = promise;
	async_send->send = (struct io_sock_stream_send)IO_SOCK_STREAM_SEND_INIT(
			&async_send->send, buf, nbytes, flags, exec,
			&io_sock_stream_async_send_func);

	io_sock_stream_submit_send(sock, &async_send->send);

	if (psend)
		*psend = &async_send->send;

	return ev_promise_get_future(promise);
}

struct io_sock_stream_connect *
io_sock_stream_connect_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_stream_connect, task)
			: NULL;
	// clang-format on
}

struct io_sock_stream_recvmsg *
io_sock_stream_recvmsg_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_stream_recvmsg, task)
			: NULL;
	// clang-format on
}

struct io_sock_stream_recv *
io_sock_stream_recv_from_task(struct ev_task *task)
{
	struct io_sock_stream_recvmsg *recvmsg =
			io_sock_stream_recvmsg_from_task(task);
	// clang-format off
	return recvmsg ? structof(recvmsg, struct io_sock_stream_recv, recvmsg)
			: NULL;
	// clang-format on
}

struct io_sock_stream_sendmsg *
io_sock_stream_sendmsg_from_task(struct ev_task *task)
{
	// clang-format off
	return task ? structof(task, struct io_sock_stream_sendmsg, task)
			: NULL;
	// clang-format on
}

struct io_sock_stream_send *
io_sock_stream_send_from_task(struct ev_task *task)
{
	struct io_sock_stream_sendmsg *sendmsg =
			io_sock_stream_sendmsg_from_task(task);
	// clang-format off
	return sendmsg ? structof(sendmsg, struct io_sock_stream_send, sendmsg)
			: NULL;
	// clang-format on
}

static void
io_sock_stream_async_connect_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_connect *connect =
			io_sock_stream_connect_from_task(task);
	struct io_sock_stream_async_connect *async_connect = structof(
			connect, struct io_sock_stream_async_connect, connect);

	ev_promise_set(async_connect->promise, &connect->errc);
	ev_promise_release(async_connect->promise);
}

static void
io_sock_stream_async_recvmsg_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_recvmsg *recvmsg =
			io_sock_stream_recvmsg_from_task(task);
	struct io_sock_stream_async_recvmsg *async_recvmsg = structof(
			recvmsg, struct io_sock_stream_async_recvmsg, recvmsg);

	*async_recvmsg->flags = recvmsg->flags;
	ev_promise_set(async_recvmsg->promise, &recvmsg->r);
	ev_promise_release(async_recvmsg->promise);
}

static void
io_sock_stream_async_recv_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_recv *recv = io_sock_stream_recv_from_task(task);
	struct io_sock_stream_async_recv *async_recv =
			structof(recv, struct io_sock_stream_async_recv, recv);

	*async_recv->flags = recv->recvmsg.flags;
	ev_promise_set(async_recv->promise, &recv->recvmsg.r);
	ev_promise_release(async_recv->promise);
}

static void
io_sock_stream_async_sendmsg_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_sendmsg *sendmsg =
			io_sock_stream_sendmsg_from_task(task);
	struct io_sock_stream_async_sendmsg *async_sendmsg = structof(
			sendmsg, struct io_sock_stream_async_sendmsg, sendmsg);

	ev_promise_set(async_sendmsg->promise, &sendmsg->r);
	ev_promise_release(async_sendmsg->promise);
}

static void
io_sock_stream_async_send_func(struct ev_task *task)
{
	assert(task);
	struct io_sock_stream_send *send = io_sock_stream_send_from_task(task);
	struct io_sock_stream_async_send *async_send =
			structof(send, struct io_sock_stream_async_send, send);

	ev_promise_set(async_send->promise, &send->sendmsg.r);
	ev_promise_release(async_send->promise);
}
