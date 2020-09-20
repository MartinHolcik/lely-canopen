/**@file
 * This file is part of the utilities library; it contains the implementation of
 * the round-robin coroutine scheduler.
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
#include <lely/util/rand.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

static coro_sched_t *coro_sched_ws_impl_create(coro_sched_ctor_t *ctor);
static void coro_sched_ws_impl_destroy(
		coro_sched_ctor_t *ctor, coro_sched_t *sched);

// clang-format off
static const struct coro_sched_ctor_vtbl coro_sched_ws_ctor_vtbl = {
	&coro_sched_ws_impl_create,
	&coro_sched_ws_impl_destroy
};
// clang-format on

static void coro_sched_ws_impl_push(coro_sched_t *sched, coro_t coro);
static coro_t coro_sched_ws_impl_pop(coro_sched_t *sched);
static void coro_sched_ws_impl_wait(
		coro_sched_t *sched, const struct timespec *tp);
static void coro_sched_ws_impl_signal(coro_sched_t *sched);

// clang-format off
static const struct coro_sched_vtbl coro_sched_ws_impl_vtbl = {
	&coro_sched_ws_impl_push,
	&coro_sched_ws_impl_pop,
	&coro_sched_ws_impl_wait,
	&coro_sched_ws_impl_signal
};
// clang-format on

struct coro_sched_ws_impl {
	const struct coro_sched_vtbl *vptr;
	uint_least32_t id;
	size_t nsteal;
	rand_u32_t r;
#if !LELY_NO_THREADS
	mtx_t mtx;
	cnd_t cond;
#endif
	int flag;
	struct dllist queue;
};

static inline struct coro_sched_ws_impl *coro_sched_ws_impl_from_sched(
		coro_sched_t *sched);

static int coro_sched_ws_impl_insert(struct coro_sched_ws_impl *impl);
static void coro_sched_ws_impl_remove(struct coro_sched_ws_impl *impl);

static struct dlnode *coro_sched_ws_impl_steal(struct coro_sched_ws_impl *impl);

#if LELY_NO_THREADS
static size_t coro_sched_ws_nsteal;
#else
static _Thread_local size_t coro_sched_ws_nsteal;
static mtx_t coro_sched_ws_mtx;
#endif
static struct coro_sched_ws_impl **coro_sched_ws_impls;
static size_t coro_sched_ws_nimpl;

static void coro_sched_ws_init(void);

coro_sched_ctor_t *
coro_sched_ws_ctor(size_t nsteal)
{
	static const struct coro_sched_ctor_vtbl *const vptr =
			&coro_sched_ws_ctor_vtbl;

	coro_sched_ws_nsteal = nsteal;

	return &vptr;
}

static coro_sched_t *
coro_sched_ws_impl_create(coro_sched_ctor_t *ctor)
{
	(void)ctor;

#if LELY_NO_THREADS
	static int flag;
	if (!flag) {
		flag = 1;
		coro_sched_ws_init();
	}
#else
	static once_flag flag;
	call_once(&flag, &coro_sched_ws_init);
#endif

	int errc = 0;

	struct coro_sched_ws_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		errc = errno2c(errno);
		goto error_malloc_impl;
	}

	impl->vptr = &coro_sched_ws_impl_vtbl;

	impl->id = 0;

	impl->nsteal = coro_sched_ws_nsteal;
	rand_u32_seed(&impl->r, (uintptr_t)(void *)impl);

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

	dllist_init(&impl->queue);

	if (coro_sched_ws_impl_insert(impl) == -1) {
		errc = get_errc();
		goto error_insert_impl;
	}

	return &impl->vptr;

	// coro_sched_ws_impl_remove(impl);
error_insert_impl:
#if !LELY_NO_THREADS
	cnd_destroy(&impl->cond);
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
coro_sched_ws_impl_destroy(coro_sched_ctor_t *ctor, coro_sched_t *sched)
{
	(void)ctor;

	if (sched) {
		struct coro_sched_ws_impl *impl =
				coro_sched_ws_impl_from_sched(sched);

		coro_sched_ws_impl_remove(impl);

#if !LELY_NO_THREADS
		cnd_destroy(&impl->cond);
		mtx_destroy(&impl->mtx);
#endif
		free(impl);
	}
}

static void
coro_sched_ws_impl_push(coro_sched_t *sched, coro_t coro)
{
	struct coro_sched_ws_impl *impl = coro_sched_ws_impl_from_sched(sched);
	assert(coro);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	dllist_push_back(&impl->queue, &coro->node);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
}

static coro_t
coro_sched_ws_impl_pop(coro_sched_t *sched)
{
	struct coro_sched_ws_impl *impl = coro_sched_ws_impl_from_sched(sched);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct dlnode *node = dllist_pop_front(&impl->queue);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
	if (!node)
		node = coro_sched_ws_impl_steal(impl);
	return node ? structof(node, struct coro, node) : NULL;
}

static void
coro_sched_ws_impl_wait(coro_sched_t *sched, const struct timespec *tp)
{
	struct coro_sched_ws_impl *impl = coro_sched_ws_impl_from_sched(sched);

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
coro_sched_ws_impl_signal(coro_sched_t *sched)
{
	struct coro_sched_ws_impl *impl = coro_sched_ws_impl_from_sched(sched);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	impl->flag = 1;
#if !LELY_NO_THREADS
	cnd_signal(&impl->cond);
	mtx_unlock(&impl->mtx);
#endif
}

static inline struct coro_sched_ws_impl *
coro_sched_ws_impl_from_sched(coro_sched_t *sched)
{
	assert(sched);

	return structof(sched, struct coro_sched_ws_impl, vptr);
}

static int
coro_sched_ws_impl_insert(struct coro_sched_ws_impl *impl)
{
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&coro_sched_ws_mtx);
#endif

	if (coro_sched_ws_nimpl == UINT32_MAX - 1) {
#if !LELY_NO_THREADS
		mtx_unlock(&coro_sched_ws_mtx);
#endif
		set_errnum(ERRNUM_NOMEM);
		return -1;
	}

	struct coro_sched_ws_impl **impls = realloc(coro_sched_ws_impls,
			(coro_sched_ws_nimpl + 1) * sizeof(*impls));
	if (!impls) {
#if !LELY_NO_THREADS
		mtx_unlock(&coro_sched_ws_mtx);
#endif
		return -1;
	}
	coro_sched_ws_impls = impls;

	impl->id = coro_sched_ws_nimpl++;
	coro_sched_ws_impls[impl->id] = impl;

#if !LELY_NO_THREADS
	mtx_unlock(&coro_sched_ws_mtx);
#endif

	return 0;
}

static void
coro_sched_ws_impl_remove(struct coro_sched_ws_impl *impl)
{
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&coro_sched_ws_mtx);
#endif
	assert(coro_sched_ws_nimpl > impl->id);
	// Swap the last element with the element being removed.
	coro_sched_ws_impls[impl->id] =
			coro_sched_ws_impls[--coro_sched_ws_nimpl];
	coro_sched_ws_impls[impl->id]->id = impl->id;
	// Reduce the size of the array, or free it if it is empty.
	if (coro_sched_ws_nimpl) {
		struct coro_sched_ws_impl **impls = realloc(coro_sched_ws_impls,
				coro_sched_ws_nimpl * sizeof(*impls));
		// Reducing the size of the array should never fail.
		assert(impls);
		coro_sched_ws_impls = impls;
	} else {
		free(coro_sched_ws_impls);
		coro_sched_ws_impls = NULL;
	}
#if !LELY_NO_THREADS
	mtx_unlock(&coro_sched_ws_mtx);
#endif
}

static struct dlnode *
coro_sched_ws_impl_steal(struct coro_sched_ws_impl *impl)
{
	assert(impl);

	if (!impl->nsteal)
		return NULL;

	struct dllist queue;
	dllist_init(&queue);

	// Keep trying until we've stolen at least one coroutine.
	for (uint_least32_t i = 0; dllist_empty(&queue) && i < impl->nsteal;
			i++) {
		// Pick a random scheduler to steal from.
		uint_least32_t id = rand_u32_get(&impl->r);
#if !LELY_NO_THREADS
		mtx_lock(&coro_sched_ws_mtx);
#endif
		id %= coro_sched_ws_nimpl;
		if (id == impl->id) {
#if !LELY_NO_THREADS
			mtx_unlock(&coro_sched_ws_mtx);
#endif
			continue;
		}
		struct coro_sched_ws_impl *victim = coro_sched_ws_impls[id];
#if !LELY_NO_THREADS
		mtx_lock(&victim->mtx);
#endif
		// Steal every other coroutine that is not pinned to a thread.
		int steal = 1;
		dllist_foreach (&victim->queue, node) {
			if (coro_is_pinned(structof(node, struct coro, node))) {
				steal = 1;
				continue;
			}
			if (steal) {
				dllist_remove(&victim->queue, node);
				dllist_push_back(&queue, node);
			}
			steal = !steal;
		}
#if !LELY_NO_THREADS
		mtx_unlock(&victim->mtx);
		mtx_unlock(&coro_sched_ws_mtx);
#endif
	}

	// Assign the stolen coroutines to this scheduler.
	dllist_foreach (&queue, node) {
		coro_t coro = structof(node, struct coro, node);
		coro_set_sched(coro, &impl->vptr);
	}

	struct dlnode *node = dllist_pop_front(&queue);

	if (!dllist_empty(&queue)) {
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		dllist_append(&impl->queue, &queue);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}

	return node;
}

static void
coro_sched_ws_init(void)
{
#if !LELY_NO_THREADS
	mtx_init(&coro_sched_ws_mtx, mtx_plain);
#endif
	coro_sched_ws_impls = NULL;
	coro_sched_ws_nimpl = 0;
}
