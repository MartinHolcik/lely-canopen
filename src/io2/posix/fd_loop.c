/**@file
 * This file is part of the I/O library; it contains the file descriptor event
 * loop implementation.
 *
 * @see lely/io2/posix/fd_loop.h
 *
 * @copyright 2020 Lely Industries N.V.
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

#include "io.h"

#if _POSIX_C_SOURCE >= 200112L

#if !LELY_NO_THREADS
#include <lely/libc/stdatomic.h>
#endif
#include <lely/ev/std_exec.h>
#include <lely/ev/task.h>
#include <lely/io2/posix/fd_loop.h>
#include <lely/util/sllist.h>
#include <lely/util/util.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#if !LELY_NO_THREADS
#include <pthread.h>
#endif
#include <unistd.h>

#ifdef __linux__
#include <sys/eventfd.h>
#else
#include "fd.h"
#endif

static void io_fd_loop_std_exec_impl_on_task_init(ev_std_exec_impl_t *impl);
static void io_fd_loop_std_exec_impl_on_task_fini(ev_std_exec_impl_t *impl);
static void io_fd_loop_std_exec_impl_post(
		ev_std_exec_impl_t *impl, struct ev_task *task);
static size_t io_fd_loop_std_exec_impl_abort(
		ev_std_exec_impl_t *impl, struct ev_task *task);

// clang-format off
static const struct ev_std_exec_impl_vtbl io_fd_loop_std_exec_impl_vtbl = {
	&io_fd_loop_std_exec_impl_on_task_init,
	&io_fd_loop_std_exec_impl_on_task_fini,
	&io_fd_loop_std_exec_impl_post,
	&io_fd_loop_std_exec_impl_abort
};
// clang-format on

static int io_fd_loop_svc_notify_fork(struct io_svc *svc, enum io_fork_event e);
static void io_fd_loop_svc_shutdown(struct io_svc *svc);

// clang-format off
static const struct io_svc_vtbl io_fd_loop_svc_vtbl = {
	&io_fd_loop_svc_notify_fork,
	&io_fd_loop_svc_shutdown
};
// clang-format on

/// A file descriptor event loop.
struct io_fd_loop {
	/**
	 * A pointer to the I/O polling instance used to monitor the event loop.
	 */
	io_poll_t *poll;
	/// The I/O service representing the event loop.
	struct io_svc svc;
	/**
	 * A pointer to the I/O context with which the event loop is registered.
	 */
	io_ctx_t *ctx;
	/**
	 * A pointer to the virtual table containing the interface used by the
	 * standard executor (#exec).
	 */
	const struct ev_std_exec_impl_vtbl *impl_vptr;
	/// The executor corresponding to the event loop.
	struct ev_std_exec exec;
	/// The object used to monitor the file descriptor for I/O events.
	struct io_poll_watch watch;
	/// The file descriptor corresponding to the event loop.
	int fd[2];
#ifndef __linux__
	int wfd;
#endif
#if !LELY_NO_THREADS
	/// The mutex protecting the task queue.
	pthread_mutex_t mtx;
#endif
	unsigned shutdown : 1;
	unsigned stopped : 1;
	unsigned running : 1;
	/**
	 * The number of pending tasks. This equals the number tasks in #queue
	 * plus the number of calls to ev_exec_on_task_init() minus those to
	 * ev_exec_on_task_fini(). ev_loop_stop() is called once this value
	 * reaches 0.
	 */
#if LELY_NO_THREADS || LELY_NO_ATOMICS
	size_t ntasks;
#else
	atomic_size_t ntasks;
#endif
	/// The queue of pending tasks.
	struct sllist queue;
};

static inline io_fd_loop_t *io_fd_loop_from_impl(
		const ev_std_exec_impl_t *impl);
static inline io_fd_loop_t *io_fd_loop_from_svc(const struct io_svc *svc);

static void io_fd_loop_watch_func(struct io_poll_watch *watch, int events);

static struct ev_task *io_fd_loop_do_pop(io_fd_loop_t *loop);

static int io_fd_loop_open(io_fd_loop_t *loop);
static int io_fd_loop_close(io_fd_loop_t *loop);
static int io_fd_loop_read(io_fd_loop_t *loop);
static int io_fd_loop_write(io_fd_loop_t *loop);

void *
io_fd_loop_alloc(void)
{
	return malloc(sizeof(io_fd_loop_t));
}

void
io_fd_loop_free(void *ptr)
{
	free(ptr);
}

io_fd_loop_t *
io_fd_loop_init(io_fd_loop_t *loop, io_poll_t *poll)
{
	assert(loop);
	assert(poll);

	int errsv = 0;

	loop->poll = poll;

	loop->svc = (struct io_svc)IO_SVC_INIT(&io_fd_loop_svc_vtbl);
	loop->ctx = io_poll_get_ctx(loop->poll);
	assert(loop->ctx);

	loop->impl_vptr = &io_fd_loop_std_exec_impl_vtbl;
	ev_std_exec_init(io_fd_loop_get_exec(loop), &loop->impl_vptr);

	loop->watch = (struct io_poll_watch)IO_POLL_WATCH_INIT(
			&io_fd_loop_watch_func);

	loop->fd[1] = loop->fd[0] = -1;

#if !LELY_NO_THREADS
	if ((errsv = pthread_mutex_init(&loop->mtx, NULL)))
		goto error_init_mtx;
#endif

	loop->shutdown = 0;
	loop->stopped = 0;
	loop->running = 0;

#if LELY_NO_THREADS || LELY_NO_ATOMICS
	loop->ntasks = 0;
#else
	atomic_init(&loop->ntasks, 0);
#endif
	sllist_init(&loop->queue);

	if (io_fd_loop_open(loop) == -1) {
		errsv = errno;
		goto error_open;
	}

	return loop;

	io_ctx_insert(loop->ctx, &loop->svc);

	// io_fd_loop_close(loop);
error_open:
#if !LELY_NO_THREADS
	pthread_mutex_destroy(&loop->mtx);
error_init_mtx:
#endif
	errno = errsv;
	return NULL;
}

void
io_fd_loop_fini(io_fd_loop_t *loop)
{
	assert(loop);

	io_ctx_remove(loop->ctx, &loop->svc);

	io_fd_loop_close(loop);

#if !LELY_NO_THREADS
	pthread_mutex_destroy(&loop->mtx);
#endif
}

io_fd_loop_t *
io_fd_loop_create(io_poll_t *poll)
{
	int errsv = 0;

	io_fd_loop_t *loop = io_fd_loop_alloc();
	if (!loop) {
		errsv = errno;
		goto error_alloc;
	}

	io_fd_loop_t *tmp = io_fd_loop_init(loop, poll);
	if (!tmp) {
		errsv = errno;
		goto error_init;
	}
	loop = tmp;

	return loop;

error_init:
	io_fd_loop_free(loop);
error_alloc:
	errno = errsv;
	return NULL;
}

void
io_fd_loop_destroy(io_fd_loop_t *loop)
{
	if (loop) {
		io_fd_loop_fini(loop);
		io_fd_loop_free(loop);
	}
}

ev_poll_t *
io_fd_loop_get_poll(const io_fd_loop_t *loop)
{
	assert(loop);

	return io_poll_get_poll(loop->poll);
}

ev_exec_t *
io_fd_loop_get_exec(const io_fd_loop_t *loop)
{
	assert(loop);

	return &loop->exec.exec_vptr;
}

int
io_fd_loop_get_fd(const io_fd_loop_t *loop)
{
	assert(loop);

	return loop->fd[0];
}

void
io_fd_loop_stop(io_fd_loop_t *loop)
{
	assert(loop);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	loop->stopped = 1;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif
}

int
io_fd_loop_stopped(io_fd_loop_t *loop)
{
#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	int stopped = loop->stopped;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif
	return stopped;
}

void
io_fd_loop_restart(io_fd_loop_t *loop)
{
	assert(loop);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	loop->stopped = 0;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif
}

size_t
io_fd_loop_run(io_fd_loop_t *loop)
{
	size_t n = 0;
	while (io_fd_loop_run_one(loop))
		n += n < SIZE_MAX;
	return n;
}

size_t
io_fd_loop_run_one(io_fd_loop_t *loop)
{
	assert(loop);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	struct ev_task *task = io_fd_loop_do_pop(loop);
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif
	if (!task)
		return 0;

	assert(task->exec);
	ev_exec_run(task->exec, task);

	return 1;
}

static void
io_fd_loop_std_exec_impl_on_task_init(ev_std_exec_impl_t *impl)
{
	io_fd_loop_t *loop = io_fd_loop_from_impl(impl);

#if LELY_NO_THREADS || LELY_NO_ATOMICS
	loop->ntasks++;
#else
	atomic_fetch_add_explicit(&loop->ntasks, 1, memory_order_relaxed);
#endif
}

static void
io_fd_loop_std_exec_impl_on_task_fini(ev_std_exec_impl_t *impl)
{
	io_fd_loop_t *loop = io_fd_loop_from_impl(impl);

#if LELY_NO_THREADS || LELY_NO_ATOMICS
	if (!--loop->ntasks) {
#else
	if (atomic_fetch_sub_explicit(&loop->ntasks, 1, memory_order_release)
			== 1) {
		atomic_thread_fence(memory_order_acquire);
#endif
#if !LELY_NO_THREADS
		while (pthread_mutex_lock(&loop->mtx) == EINTR)
			;
#endif
		if (sllist_empty(&loop->queue))
			loop->stopped = 1;
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&loop->mtx);
#endif
	}
}

static void
io_fd_loop_std_exec_impl_post(ev_std_exec_impl_t *impl, struct ev_task *task)
{
	io_fd_loop_t *loop = io_fd_loop_from_impl(impl);
	assert(task);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	sllist_push_back(&loop->queue, &task->_node);
	int running = !loop->shutdown && loop->running;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif

	if (!running) {
		int errsv = errno;
		if (io_fd_loop_write(loop) == -1)
			errno = errsv;
	}
}

static size_t
io_fd_loop_std_exec_impl_abort(ev_std_exec_impl_t *impl, struct ev_task *task)
{
	io_fd_loop_t *loop = io_fd_loop_from_impl(impl);

	struct sllist queue;
	sllist_init(&queue);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	if (!task)
		sllist_append(&queue, &loop->queue);
	else if (sllist_remove(&loop->queue, &task->_node))
		sllist_push_back(&queue, &task->_node);
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif

	size_t n = 0;
	while (sllist_pop_front(&queue))
		n += n < SIZE_MAX;
	return n;
}

static int
io_fd_loop_svc_notify_fork(struct io_svc *svc, enum io_fork_event e)
{
	io_fd_loop_t *loop = io_fd_loop_from_svc(svc);

	if (e != IO_FORK_CHILD || loop->shutdown)
		return 0;

	int result = 0;
	int errsv = errno;

	if (io_fd_loop_close(loop) == -1 && !result) {
		errsv = errno;
		result = -1;
	}

	if (io_fd_loop_open(loop) == -1 && !result) {
		errsv = errno;
		result = -1;
	}

	if (!sllist_empty(&loop->queue) && io_fd_loop_write(loop) == -1
			&& !result) {
		errsv = errno;
		result = -1;
	}

	errno = errsv;
	return result;
}

static void
io_fd_loop_svc_shutdown(struct io_svc *svc)
{
	io_fd_loop_t *loop = io_fd_loop_from_svc(svc);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	if (!loop->shutdown) {
		loop->shutdown = 1;
		// Stop monitoring I/O events.
		io_poll_watch(loop->poll, loop->fd[0], 0, &loop->watch);
	}
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif
}

static inline io_fd_loop_t *
io_fd_loop_from_impl(const ev_std_exec_impl_t *impl)
{
	assert(impl);

	return structof(impl, io_fd_loop_t, impl_vptr);
}

static inline io_fd_loop_t *
io_fd_loop_from_svc(const struct io_svc *svc)
{
	assert(svc);

	return structof(svc, io_fd_loop_t, svc);
}

static void
io_fd_loop_watch_func(struct io_poll_watch *watch, int events)
{
	assert(watch);
	io_fd_loop_t *loop = structof(watch, io_fd_loop_t, watch);
	(void)events;

	int errsv = errno;

	io_fd_loop_read(loop);

#if !LELY_NO_THREADS
	while (pthread_mutex_lock(&loop->mtx) == EINTR)
		;
#endif
	assert(!loop->running);
	loop->running = 1;
	struct ev_task *task;
	while (!loop->shutdown && (task = io_fd_loop_do_pop(loop))) {
#if !LELY_NO_THREADS
		pthread_mutex_unlock(&loop->mtx);
#endif
		assert(task->exec);
		ev_exec_run(task->exec, task);
#if !LELY_NO_THREADS
		while (pthread_mutex_lock(&loop->mtx) == EINTR)
			;
#endif
	}
	if (!loop->shutdown)
		io_poll_watch(loop->poll, loop->fd[0], IO_EVENT_IN, watch);
	loop->running = 0;
#if !LELY_NO_THREADS
	pthread_mutex_unlock(&loop->mtx);
#endif

	errno = errsv;
}

static struct ev_task *
io_fd_loop_do_pop(io_fd_loop_t *loop)
{
	assert(loop);

	if (loop->stopped)
		return NULL;

	struct ev_task *task =
			ev_task_from_node(sllist_pop_front(&loop->queue));
#if LELY_NO_THREADS || LELY_NO_ATOMICS
	if (!task && !loop->ntasks)
#else
	// clang-format off
	if (!task && !atomic_load_explicit((atomic_size_t *)&loop->ntasks,
			memory_order_relaxed))
	// clang-format on
#endif
		loop->stopped = 1;
	return task;
}

static int
io_fd_loop_open(io_fd_loop_t *loop)
{
	assert(loop);

	int errsv = 0;

	if (io_fd_loop_close(loop) == -1) {
		errsv = errno;
		goto error_close;
	}

#ifdef __linux__
	loop->fd[1] = loop->fd[0] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (!loop->fd[0]) {
		errsv = errno;
		goto error_eventfd;
	}
#else
	if (pipe(loop->fd) == -1) {
		errsv = errno;
		goto error_pipe;
	}

	if (io_fd_set_cloexec(loop->fd[0]) == -1
			|| io_fd_set_cloexec(loop->fd[1]) == -1) {
		errsv = errno;
		goto error_set_cloexec;
	}

	if (io_fd_set_nonblock(loop->fd[0]) == -1
			|| io_fd_set_nonblock(loop->fd[1]) == -1) {
		errsv = errno;
		goto error_set_nonblock;
	}
#endif

	if (io_poll_watch(loop->poll, loop->fd[0], IO_EVENT_IN, &loop->watch)
			== -1) {
		errsv = errno;
		goto error_poll_watch;
	}

	return 0;

error_poll_watch:
#ifdef __linux__
	close(loop->fd[0]);
error_eventfd:
#else
error_set_nonblock:
error_set_cloexec:
	close(loop->fd[1]);
	close(loop->fd[0]);
error_pipe:
#endif
	loop->fd[1] = loop->fd[0] = -1;
error_close:
	errno = errsv;
	return -1;
}

static int
io_fd_loop_close(io_fd_loop_t *loop)
{
	assert(loop);

	if (loop->fd[0] == -1)
		return 0;

	int result = 0;
	int errsv = errno;

	// clang-format off
	if (!loop->shutdown && io_poll_watch(loop->poll, loop->fd[0], 0,
			&loop->watch) == -1 && !result) {
		// clang-format on
		errsv = errno;
		result = -1;
	}

#ifndef __linux__
	if (close(loop->fd[1]) == -1 && !result) {
		errsv = errno;
		result = -1;
	}
#endif

	if (close(loop->fd[0]) == -1 && !result) {
		errsv = errno;
		result = -1;
	}

	loop->fd[1] = loop->fd[0] = -1;

	errno = errsv;
	return result;
}

static int
io_fd_loop_read(io_fd_loop_t *loop)
{
	assert(loop);

	int errsv = errno;
	for (;;) {
		errno = 0;
#ifdef __linux__
		uint64_t buf;
#else
		char buf;
#endif
		ssize_t result = read(loop->fd[0], &buf, sizeof(buf));
		if (result < 0 && errno != EINTR) {
			if (errno != EAGAIN || errno != EWOULDBLOCK)
				return -1;
			errno = errsv;
			return 0;
		}
	}
}

static int
io_fd_loop_write(io_fd_loop_t *loop)
{
	assert(loop);

	int errsv = errno;
	ssize_t result;
	do {
		errno = 0;
#ifdef __linux__
		uint64_t buf = 1;
#else
		char buf = 0;
#endif
		result = write(loop->fd[1], &buf, sizeof(buf));
	} while (result < 0 && errno == EINTR);
	if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		return -1;
	errno = errsv;
	return result > 0 ? 1 : 0;
}

#endif // _POSIX_C_SOURCE >= 200112L
