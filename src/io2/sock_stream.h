/**@file
 * This is the internal header file of the stream socket operation queue
 * functions.
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

#ifndef LELY_IO2_INTERN_SOCK_STREAM_H_
#define LELY_IO2_INTERN_SOCK_STREAM_H_

#include "stream.h"
#include <lely/io2/sock_stream.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static void io_sock_stream_connect_post(
		struct io_sock_stream_connect *connect, int errc);
static size_t io_sock_stream_connect_queue_post(struct sllist *queue, int errc);

static void io_sock_stream_recvmsg_post(struct io_sock_stream_recvmsg *recvmsg,
		ssize_t result, int errc);
static void io_sock_stream_recv_post(
		struct ev_task *task, ssize_t result, int errc);
static size_t io_sock_stream_recv_queue_post(
		struct sllist *queue, ssize_t result, int errc);

static void io_sock_stream_sendmsg_post(struct io_sock_stream_sendmsg *sendmsg,
		ssize_t result, int errc);
static void io_sock_stream_send_post(
		struct ev_task *task, ssize_t result, int errc);
static size_t io_sock_stream_send_queue_post(
		struct sllist *queue, ssize_t result, int errc);

static inline void
io_sock_stream_connect_post(struct io_sock_stream_connect *connect, int errc)
{
	connect->errc = errc;

	ev_exec_t *exec = connect->task.exec;
	ev_exec_post(exec, &connect->task);
	ev_exec_on_task_fini(exec);
}

static inline size_t
io_sock_stream_connect_queue_post(struct sllist *queue, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_sock_stream_connect *connect =
				io_sock_stream_connect_from_task(task);
		io_sock_stream_connect_post(connect, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

static inline void
io_sock_stream_recvmsg_post(struct io_sock_stream_recvmsg *recvmsg,
		ssize_t result, int errc)
{
	recvmsg->task._data = NULL;
	recvmsg->r.result = result;
	recvmsg->r.errc = errc;

	ev_exec_t *exec = recvmsg->task.exec;
	ev_exec_post(exec, &recvmsg->task);
	ev_exec_on_task_fini(exec);
}

static void
io_sock_stream_recv_post(struct ev_task *task, ssize_t result, int errc)
{
	int is_recvmsg = (uintptr_t)task->_data != 0;
	if (is_recvmsg) {
		struct io_sock_stream_recvmsg *recvmsg =
				io_sock_stream_recvmsg_from_task(task);
		io_sock_stream_recvmsg_post(recvmsg, result, errc);
	} else {
		struct io_stream_readv *readv = io_stream_readv_from_task(task);
		io_stream_readv_post(readv, result, errc);
	}
}

static inline size_t
io_sock_stream_recv_queue_post(struct sllist *queue, ssize_t result, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		io_sock_stream_recv_post(task, result, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

static inline void
io_sock_stream_sendmsg_post(struct io_sock_stream_sendmsg *sendmsg,
		ssize_t result, int errc)
{
	sendmsg->task._data = NULL;
	sendmsg->r.result = result;
	sendmsg->r.errc = errc;

	ev_exec_t *exec = sendmsg->task.exec;
	ev_exec_post(exec, &sendmsg->task);
	ev_exec_on_task_fini(exec);
}

static void
io_sock_stream_send_post(struct ev_task *task, ssize_t result, int errc)
{
	int is_sendmsg = (uintptr_t)task->_data != 0;
	if (is_sendmsg) {
		struct io_sock_stream_sendmsg *sendmsg =
				io_sock_stream_sendmsg_from_task(task);
		io_sock_stream_sendmsg_post(sendmsg, result, errc);
	} else {
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		io_stream_writev_post(writev, result, errc);
	}
}

static inline size_t
io_sock_stream_send_queue_post(struct sllist *queue, ssize_t result, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		io_sock_stream_send_post(task, result, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_INTERN_SOCK_STREAM_H_
