/**@file
 * This file is part of the I/O library; it contains the implementation of the
 * user-defined stream.
 *
 * @see lely/io2/user/stream.h
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or useried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../stream.h"
#include <lely/libc/stdint.h>
#if !LELY_NO_THREADS
#include <lely/libc/threads.h>
#endif
#include <lely/io2/ctx.h>
#include <lely/io2/user/stream.h>
#include <lely/util/cbuf.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

#ifndef LELY_IO_USER_STREAM_RXLEN
/// The default receive queue length (in bytes) of the user-defined stream.
#define LELY_IO_USER_STREAM_RXLEN 65535
#endif

static io_ctx_t *io_user_stream_dev_get_ctx(const io_dev_t *dev);
static ev_exec_t *io_user_stream_dev_get_exec(const io_dev_t *dev);
static size_t io_user_stream_dev_cancel(io_dev_t *dev, struct ev_task *task);
static size_t io_user_stream_dev_abort(io_dev_t *dev, struct ev_task *task);

// clang-format off
static const struct io_dev_vtbl io_user_stream_dev_vtbl = {
	&io_user_stream_dev_get_ctx,
	&io_user_stream_dev_get_exec,
	&io_user_stream_dev_cancel,
	&io_user_stream_dev_abort
};
// clang-format on

static io_dev_t *io_user_stream_get_dev(const io_stream_t *stream);
static ssize_t io_user_stream_readv(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_user_stream_submit_readv(
		io_stream_t *stream, struct io_stream_readv *readv);
static ssize_t io_user_stream_writev(
		io_stream_t *stream, const struct io_buf *buf, int bufcnt);
static void io_user_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev);

// clang-format off
static const struct io_stream_vtbl io_user_stream_vtbl = {
	&io_user_stream_get_dev,
	&io_user_stream_readv,
	&io_user_stream_submit_readv,
	&io_user_stream_writev,
	&io_user_stream_submit_writev
};
// clang-format on

static void io_user_stream_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_user_stream_svc_vtbl = {
	NULL,
	&io_user_stream_svc_shutdown
};
// clang-format on

struct io_user_stream {
	const struct io_dev_vtbl *dev_vptr;
	const struct io_stream_vtbl *stream_vptr;
	struct io_svc svc;
	io_ctx_t *ctx;
	ev_exec_t *exec;
	io_user_stream_write_t *func;
	void *arg;
	struct ev_task writev_task;
#if !LELY_NO_THREADS
	mtx_t mtx;
#endif
	unsigned shutdown : 1;
	unsigned eof : 1;
	unsigned writev_posted : 1;
	struct sllist readv_queue;
	struct sllist writev_queue;
#if !LELY_NO_THREADS
	mtx_t io_mtx;
#endif
	struct cbuf rxbuf;
	struct ev_task *current_task;
};

static void io_user_stream_writev_task_func(struct ev_task *task);

static inline struct io_user_stream *io_user_stream_from_dev(
		const io_dev_t *dev);
static inline struct io_user_stream *io_user_stream_from_stream(
		const io_stream_t *stream);
static inline struct io_user_stream *io_user_stream_from_svc(
		const struct io_svc *svc);

static void io_user_stream_do_pop(struct io_user_stream *user,
		struct sllist *readv_queue, struct sllist *writev_queue,
		struct ev_task *task);

static ssize_t io_user_stream_do_read(struct io_user_stream *user,
		const struct io_buf *buf, int bufcnt);

void *
io_user_stream_alloc(void)
{
	struct io_user_stream *user = malloc(sizeof(*user));
	if (!user)
		set_errc(errno2c(errno));
	return user ? &user->stream_vptr : NULL;
}

void
io_user_stream_free(void *ptr)
{
	if (ptr)
		free(io_user_stream_from_stream(ptr));
}

io_stream_t *
io_user_stream_init(io_stream_t *stream, io_ctx_t *ctx, ev_exec_t *exec,
		size_t rxlen, io_user_stream_write_t *func, void *arg)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);
	assert(ctx);
	assert(exec);

	if (!rxlen)
		rxlen = LELY_IO_USER_STREAM_RXLEN;

	int errsv = 0;

	user->dev_vptr = &io_user_stream_dev_vtbl;
	user->stream_vptr = &io_user_stream_vtbl;

	user->svc = (struct io_svc)IO_SVC_INIT(&io_user_stream_svc_vtbl);
	user->ctx = ctx;

	user->exec = exec;

	user->func = func;
	user->arg = arg;

	user->writev_task = (struct ev_task)EV_TASK_INIT(
			user->exec, &io_user_stream_writev_task_func);

#if !LELY_NO_THREADS
	if (mtx_init(&user->mtx, mtx_plain) != thrd_success) {
		errsv = get_errc();
		goto error_init_mtx;
	}
#endif

	user->shutdown = 0;
	user->eof = 0;
	user->writev_posted = 0;

	sllist_init(&user->readv_queue);
	sllist_init(&user->writev_queue);

#if !LELY_NO_THREADS
	if (mtx_init(&user->io_mtx, mtx_plain) != thrd_success) {
		errsv = get_errc();
		goto error_init_io_mtx;
	}
#endif

	if (cbuf_init(&user->rxbuf, rxlen) == -1) {
		errsv = get_errc();
		goto error_init_rxbuf;
	}

	user->current_task = NULL;

	io_ctx_insert(user->ctx, &user->svc);

	return stream;

	cbuf_fini(&user->rxbuf);
error_init_rxbuf:
#if !LELY_NO_THREADS
	mtx_destroy(&user->io_mtx);
error_init_io_mtx:
	mtx_destroy(&user->mtx);
error_init_mtx:
#endif
	set_errc(errsv);
	return NULL;
}

void
io_user_stream_fini(io_stream_t *stream)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);

	io_ctx_remove(user->ctx, &user->svc);
	// Cancel all pending tasks.
	io_user_stream_svc_shutdown(&user->svc);

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
	// If necessary, busy-wait until io_user_stream_writev_task_func()
	// completes.
	while (user->writev_posted) {
		mtx_unlock(&user->mtx);
		thrd_yield();
		mtx_lock(&user->mtx);
	}
	mtx_unlock(&user->mtx);
#endif

	cbuf_fini(&user->rxbuf);

#if !LELY_NO_THREADS
	mtx_destroy(&user->io_mtx);
	mtx_destroy(&user->mtx);
#endif
}

io_stream_t *
io_user_stream_create(io_ctx_t *ctx, ev_exec_t *exec, size_t rxlen,
		io_user_stream_write_t *func, void *arg)
{
	int errc = 0;

	io_stream_t *stream = io_user_stream_alloc();
	if (!stream) {
		errc = get_errc();
		goto error_alloc;
	}

	io_stream_t *tmp = io_user_stream_init(
			stream, ctx, exec, rxlen, func, arg);
	if (!tmp) {
		errc = get_errc();
		goto error_init;
	}
	stream = tmp;

	return stream;

error_init:
	io_user_stream_free((void *)stream);
error_alloc:
	set_errc(errc);
	return NULL;
}

void
io_user_stream_destroy(io_stream_t *stream)
{
	if (stream) {
		io_user_stream_fini(stream);
		io_user_stream_free((void *)stream);
	}
}

int
io_user_stream_on_read(io_stream_t *stream, const void *buf, size_t nbytes)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif

	if (user->eof) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		return 0;
	}

	if (!nbytes) {
		user->eof = 1;
		sllist_append(&queue, &user->readv_queue);
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		return io_stream_readv_queue_post(&queue, 0, 0) != 0;
	}

	struct slnode *node;
	while (nbytes && (node = sllist_pop_front(&user->readv_queue))) {
		struct ev_task *task = ev_task_from_node(node);
		struct io_stream_readv *readv = io_stream_readv_from_task(task);

		readv->r.result = 0;
		readv->r.errc = 0;
		for (int i = 0; i < readv->bufcnt; i++) {
			size_t n = MIN(readv->buf[i].len, nbytes);
			memcpy(readv->buf[i].base, buf, n);
			buf = (const char *)buf + n;
			nbytes -= n;
			readv->r.result += n;
		}

		sllist_push_back(&queue, &task->_node);
	}

#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	if (nbytes) {
#if !LELY_NO_THREADS
		mtx_lock(&user->io_mtx);
#endif
		cbuf_write(&user->rxbuf, buf, nbytes);
#if !LELY_NO_THREADS
		mtx_unlock(&user->io_mtx);
#endif
	}

	return ev_task_queue_post(&queue) != 0;
}

static io_ctx_t *
io_user_stream_dev_get_ctx(const io_dev_t *dev)
{
	const struct io_user_stream *user = io_user_stream_from_dev(dev);

	return user->ctx;
}

static ev_exec_t *
io_user_stream_dev_get_exec(const io_dev_t *dev)
{
	const struct io_user_stream *user = io_user_stream_from_dev(dev);

	return user->exec;
}

static size_t
io_user_stream_dev_cancel(io_dev_t *dev, struct ev_task *task)
{
	struct io_user_stream *user = io_user_stream_from_dev(dev);

	size_t n = 0;

	struct sllist readv_queue, writev_queue;
	sllist_init(&readv_queue);
	sllist_init(&writev_queue);

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	if (user->current_task && (!task || task == user->current_task)) {
		user->current_task = NULL;
		n++;
	}
	io_user_stream_do_pop(user, &readv_queue, &writev_queue, task);
#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	size_t nread = io_stream_readv_queue_post(
			&readv_queue, -1, errnum2c(ERRNUM_CANCELED));
	n = n < SIZE_MAX - nread ? n + nread : SIZE_MAX;
	size_t nwrite = io_stream_writev_queue_post(
			&writev_queue, -1, errnum2c(ERRNUM_CANCELED));
	n = n < SIZE_MAX - nwrite ? n + nwrite : SIZE_MAX;

	return n;
}

static size_t
io_user_stream_dev_abort(io_dev_t *dev, struct ev_task *task)
{
	struct io_user_stream *user = io_user_stream_from_dev(dev);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	io_user_stream_do_pop(user, &queue, &queue, task);
#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	return ev_task_queue_abort(&queue);
}

static io_dev_t *
io_user_stream_get_dev(const io_stream_t *stream)
{
	const struct io_user_stream *user = io_user_stream_from_stream(stream);

	return &user->dev_vptr;
}

static ssize_t
io_user_stream_readv(io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);

	ssize_t n = io_buf_size(buf, bufcnt);
	if (n <= 0)
		return n;

#if !LELY_NO_THREADS
	mtx_lock(&user->io_mtx);
#endif
	ssize_t result = io_user_stream_do_read(user, buf, bufcnt);
#if !LELY_NO_THREADS
	mtx_unlock(&user->io_mtx);
#endif
	if (!result) {
#if !LELY_NO_THREADS
		mtx_lock(&user->mtx);
#endif
		if (!user->eof) {
#if !LELY_NO_THREADS
			mtx_unlock(&user->mtx);
#endif
			set_errnum(ERRNUM_AGAIN);
			return -1;
		}
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
	}
	return result;
}

static void
io_user_stream_submit_readv(io_stream_t *stream, struct io_stream_readv *readv)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);
	assert(readv);
	assert(readv->buf || !readv->bufcnt);
	struct ev_task *task = &readv->task;

	if (!task->exec)
		task->exec = user->exec;
	ev_exec_on_task_init(task->exec);

	int errsv = get_errc();
	ssize_t n = io_buf_size(readv->buf, readv->bufcnt);
	if (n < 0) {
		io_stream_readv_post(readv, -1, get_errc());
		set_errc(errsv);
		return;
	}

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	if (user->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_readv_post(readv, -1, errnum2c(ERRNUM_CANCELED));
	} else if (readv->bufcnt < 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_readv_post(readv, -1, errnum2c(ERRNUM_INVAL));
	} else if (user->eof || (!n && sllist_empty(&user->readv_queue))) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_readv_post(readv, 0, 0);
	} else {
#if !LELY_NO_THREADS
		mtx_lock(&user->io_mtx);
#endif
		if (!cbuf_empty(&user->rxbuf)) {
#if !LELY_NO_THREADS
			mtx_unlock(&user->mtx);
#endif
			ssize_t result = io_user_stream_do_read(
					user, readv->buf, readv->bufcnt);
#if !LELY_NO_THREADS
			mtx_unlock(&user->io_mtx);
#endif
			io_stream_readv_post(readv, result, 0);
		} else {
#if !LELY_NO_THREADS
			mtx_unlock(&user->io_mtx);
#endif
			sllist_push_back(&user->readv_queue, &task->_node);
#if !LELY_NO_THREADS
			mtx_unlock(&user->mtx);
#endif
		}
	}
}

static ssize_t
io_user_stream_writev(io_stream_t *stream, const struct io_buf *buf, int bufcnt)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);

	ssize_t n = io_buf_size(buf, bufcnt);
	if (n <= 0)
		return n;

	if (!user->func) {
		set_errnum(ERRNUM_NOSYS);
		return -1;
	}

	ssize_t result = 0;
#if !LELY_NO_THREADS
	mtx_lock(&user->io_mtx);
#endif
	for (int i = 0; i < bufcnt; i++) {
		if (!buf[i].len)
			continue;
		n = user->func(buf[i].base, buf[i].len, user->arg);
		if (n < 0) {
#if !LELY_NO_THREADS
			int errsv = get_errc();
			mtx_unlock(&user->io_mtx);
			set_errc(errsv);
#endif
			return result ? result : -1;
		}
		assert(n <= SSIZE_MAX && result <= SSIZE_MAX - n);
		result += n;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&user->io_mtx);
#endif
	return result;
}

static void
io_user_stream_submit_writev(
		io_stream_t *stream, struct io_stream_writev *writev)
{
	struct io_user_stream *user = io_user_stream_from_stream(stream);
	assert(writev);
	struct ev_task *task = &writev->task;

	if (!task->exec)
		task->exec = user->exec;
	ev_exec_on_task_init(task->exec);

	int errsv = get_errc();
	ssize_t n = io_buf_size(writev->buf, writev->bufcnt);
	if (n < 0) {
		io_stream_writev_post(writev, -1, get_errc());
		set_errc(errsv);
		return;
	}

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	if (user->shutdown) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_writev_post(writev, -1, errnum2c(ERRNUM_CANCELED));
	} else if (writev->bufcnt < 0) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_writev_post(writev, -1, errnum2c(ERRNUM_INVAL));
	} else if (!user->func) {
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		io_stream_writev_post(writev, -1, errnum2c(ERRNUM_NOSYS));
	} else {
		int post_writev = !user->writev_posted
				&& sllist_empty(&user->writev_queue);
		sllist_push_back(&user->writev_queue, &task->_node);
		if (post_writev)
			user->writev_posted = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&user->mtx);
#endif
		if (post_writev)
			ev_exec_post(user->writev_task.exec,
					&user->writev_task);
	}
}

static void
io_user_stream_svc_shutdown(struct io_svc *svc)
{
	struct io_user_stream *user = io_user_stream_from_svc(svc);
	io_dev_t *dev = &user->dev_vptr;

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	int shutdown = !user->shutdown;
	user->shutdown = 1;
	// Abort io_user_stream_writev_task_func().
	// clang-format off
	if (shutdown && user->writev_posted
			&& ev_exec_abort(user->writev_task.exec,
					&user->writev_task))
		// clang-format on
		user->writev_posted = 0;
#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	if (shutdown)
		// Cancel all pending tasks.
		io_user_stream_dev_cancel(dev, NULL);
}

static void
io_user_stream_writev_task_func(struct ev_task *task)
{
	assert(task);
	struct io_user_stream *user =
			structof(task, struct io_user_stream, writev_task);
	io_stream_t *stream = &user->stream_vptr;

	int errsv = get_errc();

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	task = user->current_task = ev_task_from_node(
			sllist_pop_front(&user->writev_queue));
#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	ssize_t result = 0;
	int errc = 0;
	if (task) {
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		set_errc(0);
		result = io_user_stream_writev(
				stream, writev->buf, writev->bufcnt);
		if (result < 0)
			errc = get_errc();
	}

	// clang-format off
	int wouldblock = result < 0 && (errc2num(errc) == ERRNUM_AGAIN
			|| errc2num(errc) == ERRNUM_WOULDBLOCK);
	// clang-format on

#if !LELY_NO_THREADS
	mtx_lock(&user->mtx);
#endif
	if (wouldblock && task == user->current_task) {
		// Put the write operation back on the queue if it would block,
		// unless it was canceled.
		sllist_push_front(&user->writev_queue, &task->_node);
		task = NULL;
	}
	user->current_task = NULL;

	int post_writev = user->writev_posted =
			!sllist_empty(&user->writev_queue) && !user->shutdown;
#if !LELY_NO_THREADS
	mtx_unlock(&user->mtx);
#endif

	if (task) {
		if (wouldblock)
			errc = errnum2c(ERRNUM_CANCELED);
		struct io_stream_writev *writev =
				io_stream_writev_from_task(task);
		io_stream_writev_post(writev, result, errc);
	}

	if (post_writev)
		ev_exec_post(user->writev_task.exec, &user->writev_task);

	set_errc(errsv);
}

static inline struct io_user_stream *
io_user_stream_from_dev(const io_dev_t *dev)
{
	assert(dev);

	return structof(dev, struct io_user_stream, dev_vptr);
}

static inline struct io_user_stream *
io_user_stream_from_stream(const io_stream_t *stream)
{
	assert(stream);

	return structof(stream, struct io_user_stream, stream_vptr);
}

static inline struct io_user_stream *
io_user_stream_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, struct io_user_stream, svc);
}

static void
io_user_stream_do_pop(struct io_user_stream *user, struct sllist *readv_queue,
		struct sllist *writev_queue, struct ev_task *task)
{
	assert(user);
	assert(readv_queue);
	assert(writev_queue);

	if (!task) {
		sllist_append(readv_queue, &user->readv_queue);
		sllist_append(writev_queue, &user->writev_queue);
	} else if (sllist_remove(&user->readv_queue, &task->_node)) {
		sllist_push_back(readv_queue, &task->_node);
	} else if (sllist_remove(&user->writev_queue, &task->_node)) {
		sllist_push_back(writev_queue, &task->_node);
	}
}

static ssize_t
io_user_stream_do_read(struct io_user_stream *user, const struct io_buf *buf,
		int bufcnt)
{
	assert(user);
	assert(buf || !bufcnt);
	assert(bufcnt >= 0);

	ssize_t result = 0;
	for (int i = 0; i < bufcnt; i++) {
		size_t n = cbuf_read(&user->rxbuf, buf[i].base, buf[i].len);
		assert(n <= SSIZE_MAX && result <= (ssize_t)(SSIZE_MAX - n));
		result += n;
		if (n < buf[i].len)
			break;
	}
	return result;
}
