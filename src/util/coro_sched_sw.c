/**@file
 * This file is part of the utilities library; it contains the implementation of
 * the shared-work coroutine scheduler.
 *
 * @see lely/util/coro_sched.h
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

#include "util.h"
#if !LELY_NO_THREADS
#include <lely/libc/threads.h>
#endif
#include <lely/libc/time.h>
#include <lely/util/coro_sched.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

static coro_sched_t *coro_sched_sw_impl_create(coro_sched_ctor_t *ctor);
static void coro_sched_sw_impl_destroy(
		coro_sched_ctor_t *ctor, coro_sched_t *sched);

// clang-format off
static const struct coro_sched_ctor_vtbl coro_sched_sw_ctor_vtbl = {
	&coro_sched_sw_impl_create,
	&coro_sched_sw_impl_destroy
};
// clang-format on

static void coro_sched_sw_impl_push(coro_sched_t *sched, coro_t coro);
static coro_t coro_sched_sw_impl_pop(coro_sched_t *sched);
static void coro_sched_sw_impl_wait(
		coro_sched_t *sched, const struct timespec *tp);
static void coro_sched_sw_impl_signal(coro_sched_t *sched);

// clang-format off
static const struct coro_sched_vtbl coro_sched_sw_impl_vtbl = {
	&coro_sched_sw_impl_push,
	&coro_sched_sw_impl_pop,
	&coro_sched_sw_impl_wait,
	&coro_sched_sw_impl_signal
};
// clang-format on

struct coro_sched_sw_impl {
	const struct coro_sched_vtbl *vptr;
	struct dllist queue;
#if !LELY_NO_THREADS
	mtx_t mtx;
	cnd_t cond;
#endif
	int flag;
};

static inline struct coro_sched_sw_impl *coro_sched_sw_impl_from_sched(
		coro_sched_t *sched);

#if !LELY_NO_THREADS
static mtx_t coro_sched_sw_mtx;
#endif
static struct dllist coro_sched_sw_queue;

static void coro_sched_sw_init(void);

coro_sched_ctor_t *
coro_sched_sw_ctor(void)
{
	static const struct coro_sched_ctor_vtbl *const vptr =
			&coro_sched_sw_ctor_vtbl;
	return &vptr;
}

static coro_sched_t *
coro_sched_sw_impl_create(coro_sched_ctor_t *ctor)
{
	(void)ctor;

#if LELY_NO_THREADS
	static int flag;
	if (!flag) {
		flag = 1;
		coro_sched_sw_init();
	}
#else
	static once_flag flag;
	call_once(&flag, &coro_sched_sw_init);
#endif

	int errc = 0;

	struct coro_sched_sw_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		errc = errno2c(errno);
		goto error_malloc_impl;
	}

	impl->vptr = &coro_sched_sw_impl_vtbl;

	dllist_init(&impl->queue);

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success) {
		errc = get_errc();
		goto error_init_mtx;
	}

	if (cnd_init(&impl->cond) != thrd_success) {
		errc = get_errc();
		goto error_init_cond;
	}
#endif

	impl->flag = 0;

	return &impl->vptr;

#if !LELY_NO_THREADS
	// cnd_destroy(&impl->cond);
error_init_cond:
	mtx_destroy(&impl->mtx);
error_init_mtx:
#endif
	free(impl);
error_malloc_impl:
	set_errc(errc);
	return NULL;
}

static void
coro_sched_sw_impl_destroy(coro_sched_ctor_t *ctor, coro_sched_t *sched)
{
	(void)ctor;

	if (sched) {
		struct coro_sched_sw_impl *impl =
				coro_sched_sw_impl_from_sched(sched);
#if !LELY_NO_THREADS
		cnd_destroy(&impl->cond);
		mtx_destroy(&impl->mtx);
#endif
		free(impl);
	}
}

static void
coro_sched_sw_impl_push(coro_sched_t *sched, coro_t coro)
{
	struct coro_sched_sw_impl *impl = coro_sched_sw_impl_from_sched(sched);
	assert(coro);

	if (coro_is_pinned(coro)) {
		dllist_push_back(&impl->queue, &coro->node);
	} else {
#if !LELY_NO_THREADS
		mtx_lock(&coro_sched_sw_mtx);
#endif
		dllist_push_back(&coro_sched_sw_queue, &coro->node);
#if !LELY_NO_THREADS
		mtx_unlock(&coro_sched_sw_mtx);
#endif
	}
}

static coro_t
coro_sched_sw_impl_pop(coro_sched_t *sched)
{
	struct coro_sched_sw_impl *impl = coro_sched_sw_impl_from_sched(sched);

#if !LELY_NO_THREADS
	mtx_lock(&coro_sched_sw_mtx);
#endif
	struct dlnode *node = dllist_pop_front(&coro_sched_sw_queue);
#if !LELY_NO_THREADS
	mtx_unlock(&coro_sched_sw_mtx);
#endif
	if (node) {
		coro_t coro = structof(node, struct coro, node);
		coro_set_sched(coro, sched);
	} else {
		node = dllist_pop_front(&impl->queue);
	}
	return node ? structof(node, struct coro, node) : NULL;
}

static void
coro_sched_sw_impl_wait(coro_sched_t *sched, const struct timespec *tp)
{
	struct coro_sched_sw_impl *impl = coro_sched_sw_impl_from_sched(sched);

	int errc = get_errc();
#if LELY_NO_THREADS
	while (!impl->flag && tp) {
		if (!clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, tp, NULL))
			break;
	}
	impl->flag = 0;
#else
	mtx_lock(&impl->mtx);
	while (!impl->flag) {
		if (!tp)
			cnd_wait(&impl->cond, &impl->mtx);
		else if (cnd_timedwait(&impl->cond, &impl->mtx, tp)
				== thrd_timedout)
			break;
	}
	impl->flag = 0;
	mtx_unlock(&impl->mtx);
#endif
	set_errc(errc);
}

static void
coro_sched_sw_impl_signal(coro_sched_t *sched)
{
	struct coro_sched_sw_impl *impl = coro_sched_sw_impl_from_sched(sched);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	impl->flag = 1;
#if !LELY_NO_THREADS
	cnd_signal(&impl->cond);
	mtx_unlock(&impl->mtx);
#endif
}

static inline struct coro_sched_sw_impl *
coro_sched_sw_impl_from_sched(coro_sched_t *sched)
{
	assert(sched);

	return structof(sched, struct coro_sched_sw_impl, vptr);
}

static void
coro_sched_sw_init(void)
{
#if !LELY_NO_THREADS
	mtx_init(&coro_sched_sw_mtx, mtx_plain);
#endif
	dllist_init(&coro_sched_sw_queue);
}
