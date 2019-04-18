/**@file
 * This file is part of the I/O library; it exposes the abstract I/O stream
 * functions.
 *
 * @see lely/io2/stream.h
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
#define LELY_IO_STREAM_INLINE extern inline
#include <lely/io2/stream.h>
#include <lely/util/util.h>

#include <assert.h>

struct io_stream_async_readv {
	ev_promise_t *promise;
	struct io_stream_readv readv;
};

static void io_stream_async_readv_func(struct ev_task *task);

struct io_stream_async_read {
	ev_promise_t *promise;
	struct io_stream_read read;
};

static void io_stream_async_read_func(struct ev_task *task);

struct io_stream_async_writev {
	ev_promise_t *promise;
	struct io_stream_writev writev;
};

static void io_stream_async_writev_func(struct ev_task *task);

struct io_stream_async_write {
	ev_promise_t *promise;
	struct io_stream_write write;
};

static void io_stream_async_write_func(struct ev_task *task);

ev_future_t *
io_stream_async_readv(io_stream_t *chan, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_readv **preadv)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_stream_async_readv), NULL);
	if (!promise)
		return NULL;

	struct io_stream_async_readv *async_readv = ev_promise_data(promise);
	async_readv->promise = promise;
	async_readv->readv = (struct io_stream_readv)IO_STREAM_READV_INIT(
			buf, bufcnt, exec, &io_stream_async_readv_func);

	io_stream_submit_readv(chan, &async_readv->readv);

	if (preadv)
		*preadv = &async_readv->readv;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_stream_async_read(io_stream_t *chan, ev_exec_t *exec, void *buf,
		size_t nbytes, struct io_stream_read **pread)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_stream_async_read), NULL);
	if (!promise)
		return NULL;

	struct io_stream_async_read *async_read = ev_promise_data(promise);
	async_read->promise = promise;
	async_read->read = (struct io_stream_read)IO_STREAM_READ_INIT(
			&async_read->read, buf, nbytes, exec,
			&io_stream_async_read_func);

	io_stream_submit_read(chan, &async_read->read);

	if (pread)
		*pread = &async_read->read;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_stream_async_writev(io_stream_t *chan, ev_exec_t *exec,
		const struct io_buf *buf, int bufcnt,
		struct io_stream_writev **pwritev)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_stream_async_writev), NULL);
	if (!promise)
		return NULL;

	struct io_stream_async_writev *async_writev = ev_promise_data(promise);
	async_writev->promise = promise;
	async_writev->writev = (struct io_stream_writev)IO_STREAM_WRITEV_INIT(
			buf, bufcnt, exec, &io_stream_async_writev_func);

	io_stream_submit_writev(chan, &async_writev->writev);

	if (pwritev)
		*pwritev = &async_writev->writev;

	return ev_promise_get_future(promise);
}

ev_future_t *
io_stream_async_write(io_stream_t *chan, ev_exec_t *exec, const void *buf,
		size_t nbytes, struct io_stream_write **pwrite)
{
	ev_promise_t *promise = ev_promise_create(
			sizeof(struct io_stream_async_write), NULL);
	if (!promise)
		return NULL;

	struct io_stream_async_write *async_write = ev_promise_data(promise);
	async_write->promise = promise;
	async_write->write = (struct io_stream_write)IO_STREAM_WRITE_INIT(
			&async_write->write, buf, nbytes, exec,
			&io_stream_async_write_func);

	io_stream_submit_write(chan, &async_write->write);

	if (pwrite)
		*pwrite = &async_write->write;

	return ev_promise_get_future(promise);
}

struct io_stream_readv *
io_stream_readv_from_task(struct ev_task *task)
{
	return task ? structof(task, struct io_stream_readv, task) : NULL;
}

struct io_stream_read *
io_stream_read_from_task(struct ev_task *task)
{
	struct io_stream_readv *readv = io_stream_readv_from_task(task);
	return readv ? structof(readv, struct io_stream_read, readv) : NULL;
}

struct io_stream_writev *
io_stream_writev_from_task(struct ev_task *task)
{
	return task ? structof(task, struct io_stream_writev, task) : NULL;
}

struct io_stream_write *
io_stream_write_from_task(struct ev_task *task)
{
	struct io_stream_writev *writev = io_stream_writev_from_task(task);
	return writev ? structof(writev, struct io_stream_write, writev) : NULL;
}

static void
io_stream_async_readv_func(struct ev_task *task)
{
	assert(task);
	struct io_stream_readv *readv = io_stream_readv_from_task(task);
	struct io_stream_async_readv *async_readv =
			structof(readv, struct io_stream_async_readv, readv);

	ev_promise_set(async_readv->promise, &readv->r);
	ev_promise_release(async_readv->promise);
}

static void
io_stream_async_read_func(struct ev_task *task)
{
	assert(task);
	struct io_stream_read *read = io_stream_read_from_task(task);
	struct io_stream_async_read *async_read =
			structof(read, struct io_stream_async_read, read);

	ev_promise_set(async_read->promise, &read->readv.r);
	ev_promise_release(async_read->promise);
}

static void
io_stream_async_writev_func(struct ev_task *task)
{
	assert(task);
	struct io_stream_writev *writev = io_stream_writev_from_task(task);
	struct io_stream_async_writev *async_writev =
			structof(writev, struct io_stream_async_writev, writev);

	ev_promise_set(async_writev->promise, &writev->r);
	ev_promise_release(async_writev->promise);
}

static void
io_stream_async_write_func(struct ev_task *task)
{
	assert(task);
	struct io_stream_write *write = io_stream_write_from_task(task);
	struct io_stream_async_write *async_write =
			structof(write, struct io_stream_async_write, write);

	ev_promise_set(async_write->promise, &write->writev.r);
	ev_promise_release(async_write->promise);
}
