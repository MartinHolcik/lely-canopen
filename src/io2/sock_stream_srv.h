/**@file
 * This is the internal header file of the stream socket server operation queue
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

#ifndef LELY_IO2_INTERN_SOCK_STREAM_SRV_H_
#define LELY_IO2_INTERN_SOCK_STREAM_SRV_H_

#include "io2.h"
#include <lely/ev/exec.h>
#include <lely/io2/sock_stream_srv.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static void io_sock_stream_srv_accept_post(
		struct io_sock_stream_srv_accept *accept, int errc);
static size_t io_sock_stream_srv_accept_queue_post(
		struct sllist *queue, int errc);

static inline void
io_sock_stream_srv_accept_post(
		struct io_sock_stream_srv_accept *accept, int errc)
{
	accept->errc = errc;

	ev_exec_t *exec = accept->task.exec;
	ev_exec_post(exec, &accept->task);
	ev_exec_on_task_fini(exec);
}

static inline size_t
io_sock_stream_srv_accept_queue_post(struct sllist *queue, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_sock_stream_srv_accept *accept =
				io_sock_stream_srv_accept_from_task(task);
		io_sock_stream_srv_accept_post(accept, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_INTERN_SOCK_STREAM_SRV_H_
