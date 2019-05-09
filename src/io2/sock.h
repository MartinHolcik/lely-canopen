/**@file
 * This is the internal header file of the socket operation queue functions.
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

#ifndef LELY_IO2_INTERN_SOCK_H_
#define LELY_IO2_INTERN_SOCK_H_

#include "io2.h"
#include <lely/ev/exec.h>
#include <lely/io2/sock.h>

#include <assert.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static void io_sock_wait_post(struct io_sock_wait *wait, int events, int errc);
static size_t io_sock_wait_queue_post(
		struct sllist *queue, int events, int errc);

static void io_sock_wait_queue_select(
		struct sllist *dst, struct sllist *src, int events, int errc);

static inline void
io_sock_wait_post(struct io_sock_wait *wait, int events, int errc)
{
	wait->events = events & (wait->events | IO_EVENT_ERR | IO_EVENT_HUP);
	wait->errc = errc;

	ev_exec_t *exec = wait->task.exec;
	ev_exec_post(exec, &wait->task);
	ev_exec_on_task_fini(exec);
}

static inline size_t
io_sock_wait_queue_post(struct sllist *queue, int events, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_sock_wait *wait = io_sock_wait_from_task(task);
		io_sock_wait_post(wait, events, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

static inline void
io_sock_wait_queue_select(
		struct sllist *dst, struct sllist *src, int events, int errc)
{
	assert(dst);
	assert(src);

	if (errc) {
		sllist_append(dst, src);
	} else if (events) {
		// Find operations waiting for one of the reported I/O events.
		for (struct slnode **pnode = &src->first; *pnode;
				pnode = &(*pnode)->next) {
			struct io_sock_wait *wait = io_sock_wait_from_task(
					ev_task_from_node(*pnode));
			int mask = wait->events | IO_EVENT_ERR | IO_EVENT_HUP;
			if (!(events & mask))
				continue;
			// Move the task to the other queue.
			struct slnode *next = (*pnode)->next;
			sllist_push_back(dst, &wait->task._node);
			if (!(*pnode = next)) {
				src->plast = pnode;
				break;
			}
		}
	}
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_INTERN_SOCK_H_
