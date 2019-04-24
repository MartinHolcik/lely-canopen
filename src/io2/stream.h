/**@file
 * This is the internal header file of the stream operation queue functions.
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

#ifndef LELY_IO2_INTERN_STREAM_H_
#define LELY_IO2_INTERN_STREAM_H_

#include "io2.h"
#include <lely/ev/exec.h>
#include <lely/io2/stream.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static void io_stream_readv_post(
		struct io_stream_readv *readv, ssize_t result, int errc);
static size_t io_stream_readv_queue_post(
		struct sllist *queue, ssize_t result, int errc);

static void io_stream_writev_post(
		struct io_stream_writev *writev, ssize_t result, int errc);
static size_t io_stream_writev_queue_post(
		struct sllist *queue, ssize_t result, int errc);

static inline void
io_stream_readv_post(struct io_stream_readv *readv, ssize_t result, int errc)
{
	readv->r.result = result;
	readv->r.errc = errc;

	ev_exec_t *exec = readv->task.exec;
	ev_exec_post(exec, &readv->task);
	ev_exec_on_task_fini(exec);
}

static inline size_t
io_stream_readv_queue_post(struct sllist *queue, ssize_t result, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_stream_readv *readv = io_stream_readv_from_task(task);
		io_stream_readv_post(readv, result, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

static inline void
io_stream_writev_post(struct io_stream_writev *writev, ssize_t result, int errc)
{
	writev->r.result = result;
	writev->r.errc = errc;

	ev_exec_t *exec = writev->task.exec;
	ev_exec_post(exec, &writev->task);
	ev_exec_on_task_fini(exec);
}

static inline size_t
io_stream_writev_queue_post(struct sllist *queue, ssize_t result, int errc)
{
	size_t n = 0;

	struct slnode *node;
	while ((node = sllist_pop_front(queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		io_stream_writev_post(writev, result, errc);
		n += n < SIZE_MAX;
	}

	return n;
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_INTERN_STREAM_H_
