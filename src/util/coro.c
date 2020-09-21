/**@file
 * This file is part of the utilities library; it contains the implementation of
 * the asymmetric coroutine functions.
 *
 * @see lely/util/coro.h
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
#include <lely/util/coro.h>
#include <lely/util/coro_sched.h>
#include <lely/util/errnum.h>
#include <lely/util/fiber.h>
#include <lely/util/pheap.h>
#include <lely/util/time.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>

#ifndef LELY_CORO_MINSTKSZ
/// The minimum size (in bytes) of a coroutine stack frame.
#ifdef LELY_FIBER_MINSTKSZ
#define LELY_CORO_MINSTKSZ LELY_FIBER_MINSTKSZ
#elif __WORDSIZE == 64
#define LELY_CORO_MINSTKSZ 8192
#else
#define LELY_CORO_MINSTKSZ 4096
#endif
#endif

#ifndef LELY_CORO_STKSZ
/// The default size (in bytes) of a coroutine stack frame.
#ifdef LELY_FIBER_STKSZ
#define LELY_CORO_STKSZ LELY_FIBER_STKSZ
#else
#define LELY_CORO_STKSZ 131072
#endif
#endif

extern const struct coro_sched_ctor_vtbl *const coro_sched_ctor_default_vptr;

/**
 * The implementation of an asymmetric coroutine. #coro_t is a pointer to
 * objects of this type.
 */
struct coro_impl {
	/// The identifier for this coroutine.
	struct coro coro;
	/// The fiber corresponding to this coroutine.
	fiber_t *fiber;
	/// A pointer to the scheduler managing this coroutine.
	coro_sched_t *sched;
	/// The coroutine attributes.
	struct coro_attr attr;
	/// The function to be executed in the coroutine.
	coro_start_t func;
	/// The argument to #func.
	void *arg;
	/// The result of #func, or of coro_exit() if it is invoked from #func.
	int res;
#if !LELY_NO_THREADS
	/// The mutex protecting this coroutine.
	mtx_t mtx;
#endif
	/**
	 * Indicates whether the coroutine has terminated because #func has
	 * returned or coro_exit() has been invoked.
	 */
	unsigned stopped : 1;
	/// Indicates whether the coroutine has been detached by coro_detach().
	unsigned detached : 1;
	/// A pointer to the coroutine joining with this coroutine.
	struct coro_impl *joined;
};

static fiber_t *coro_impl_fiber_func_l(fiber_t *fiber, void *arg);

static inline struct coro_impl *coro_impl_from_coro(coro_t coro);

static struct coro_impl *coro_impl_init(struct coro_impl *impl,
		const struct coro_attr *attr, coro_start_t func, void *arg);
static void coro_impl_fini(struct coro_impl *impl);

static void coro_impl_destroy(struct coro_impl *impl);

#if LELY_NO_THREADS
static struct coro_thrd {
#else
static _Thread_local struct coro_thrd {
#endif
	/**
	 * The reference counter tracking the number of calls to
	 * coro_thrd_init() minus those to coro_thrd_fini().
	 */
	size_t refcnt;
	/**
	 * A pointer to the factory used to create and destroy the coroutine
	 * scheduler for this thread.
	 */
	coro_sched_ctor_t *ctor;
	/// A pointer to the coroutine currently running on this thread.
	struct coro_impl *curr;
	/// The coroutine representing this thread.
	struct coro_impl main;
#if !LELY_NO_THREADS
	/// The mutex protecting #heap.
	mtx_t mtx;
#endif
	/**
	 * The pairing heap containing #coro_thrd_wait instances for functions
	 * waiting for a timeout.
	 */
	struct pheap heap;
	/**
	 * The helper fiber running when all coroutines for this thread are
	 * suspended.
	 */
	fiber_t *fiber;
} coro_thrd;

static fiber_t *coro_thrd_fiber_func_l(fiber_t *fiber, void *arg);

/// An object representing a function waiting for a timeout on this thread.
struct coro_thrd_wait {
	/// The function to be executed after the timeout has elapsed.
	void (*func)(void *arg);
	/// The argument to #func.
	void *arg;
	/// A pointer to the thread where the waiting function is registered.
	struct coro_thrd *thr;
	/// The node of this function in the pairing heap of the thread.
	struct pnode node;
};

/// Wakes up any functions whose timeout has elapsed.
static void coro_thrd_wake(struct coro_thrd *thr);

static fiber_t *coro_suspend_with_fiber_func(fiber_t *fiber, void *arg);

#if !LELY_NO_THREADS
static void coro_join_suspend_func_l(coro_t coro, void *arg);
#endif
static void coro_exit_suspend_func(coro_t coro, void *arg);
static void coro_yield_suspend_func(coro_t coro, void *arg);
static void coro_sleep_suspend_func(coro_t coro, void *arg);

static void coro_sleep_wait_func(void *arg);

int
coro_thrd_init(const struct coro_attr *attr, coro_sched_ctor_t *ctor)
{
	struct coro_thrd *thr = &coro_thrd;

	if (thr->refcnt++)
		return 1;

	assert(!thr->curr);

	int errc;

	struct coro_attr coro_attr =
			attr ? *attr : (struct coro_attr)CORO_ATTR_INIT;
	if (!coro_attr.stack_size)
		coro_attr.stack_size = LELY_CORO_STKSZ;
	else if (coro_attr.stack_size < LELY_CORO_MINSTKSZ)
		coro_attr.stack_size = LELY_CORO_MINSTKSZ;
#if !_WIN32
	coro_attr.stack_addr = NULL;
#endif
	attr = &coro_attr;

	struct fiber_attr fiber_attr = {
		.save_mask = attr->save_mask,
		.save_fenv = attr->save_fenv,
		.save_error = attr->save_error,
	};
	if (fiber_thrd_init(&fiber_attr) == -1) {
		errc = get_errc();
		goto error_init_thrd;
	}

	fiber_get_attr(NULL, &fiber_attr);
	coro_attr.save_mask = fiber_attr.save_mask;
	coro_attr.save_fenv = fiber_attr.save_fenv;
	coro_attr.save_error = fiber_attr.save_error;

	thr->ctor = ctor ? ctor : coro_sched_rr_ctor();
	assert(thr->ctor);

	thr->curr = &thr->main;

	thr->main.sched = coro_sched_create(thr->ctor);
	if (!thr->main.sched) {
		errc = get_errc();
		goto error_create_sched;
	}

	if (!coro_impl_init(&thr->main, &coro_attr, NULL, NULL)) {
		errc = get_errc();
		goto error_init_main;
	}
	thr->main.attr.pinned = 1;
	thr->main.detached = 1;

#if !LELY_NO_THREADS
	if (mtx_init(&thr->mtx, mtx_plain) != thrd_success) {
		errc = get_errc();
		goto error_init_mtx;
	}
#endif

	pheap_init(&thr->heap, &timespec_cmp);

	fiber_attr.stack_size = thr->main.attr.stack_size;
	thr->fiber = fiber_create(&fiber_attr, &coro_thrd_fiber_func_l, thr);
	if (!thr->fiber) {
		errc = get_errc();
		goto error_create_fiber;
	}

	return 0;

	// fiber_destroy(thr->fiber);
	// thr->fiber = NULL;
error_create_fiber:
#if !LELY_NO_THREADS
	mtx_destroy(&thr->mtx);
error_init_mtx:
#endif
	coro_impl_fini(&thr->main);
error_init_main:
	coro_sched_destroy(thr->ctor, thr->main.sched);
	thr->main.sched = NULL;
	thr->ctor = NULL;
error_create_sched:
	fiber_thrd_fini();
error_init_thrd:
	set_errc(errc);
	thr->refcnt--;
	return -1;
}

void
coro_thrd_fini(void)
{
	struct coro_thrd *thr = &coro_thrd;
	assert(thr->refcnt);
	assert(thr->curr == &thr->main);

	if (!--thr->refcnt) {
		fiber_destroy(thr->fiber);
		thr->fiber = NULL;

#if !LELY_NO_THREADS
		mtx_destroy(&thr->mtx);
#endif

		coro_impl_fini(&thr->main);

		thr->curr = NULL;

		coro_sched_destroy(thr->ctor, thr->main.sched);
		thr->main.sched = NULL;
		thr->ctor = NULL;

		fiber_thrd_fini();
	}
}

coro_sched_t *
coro_thrd_get_sched(void)
{
	return coro_thrd.main.sched;
}

int
coro_create(coro_t *coro, const struct coro_attr *attr, coro_start_t func,
		void *arg)
{
	struct coro_thrd *thr = &coro_thrd;
	assert(thr->curr);
	assert(coro);
	assert(func);

	int errc = 0;

	struct coro_attr coro_attr = attr ? *attr : thr->curr->attr;
#if !_WIN32
	if (!attr) {
		coro_attr.pinned = 0;
		coro_attr.stack_addr = NULL;
	}
	if (!coro_attr.stack_addr) {
#endif
		if (!coro_attr.stack_size)
			coro_attr.stack_size = LELY_CORO_STKSZ;
		else if (coro_attr.stack_size < LELY_CORO_MINSTKSZ)
			coro_attr.stack_size = LELY_CORO_MINSTKSZ;
#if !_WIN32
	}
#endif
	attr = &coro_attr;

	struct fiber_attr fiber_attr = {
		.save_mask = attr->save_mask,
		.save_fenv = attr->save_fenv,
		.save_error = attr->save_error,
		.guard_stack = attr->guard_stack,
		.data_size = sizeof(struct coro_impl),
		.stack_size = attr->stack_size,
#if !_WIN32
		.stack_addr = attr->stack_addr
#endif
	};
	fiber_t *fiber = fiber_create(
			&fiber_attr, &coro_impl_fiber_func_l, NULL);
	if (!fiber) {
		errc = get_errc();
		goto error_create_fiber;
	}
	fiber_get_attr(fiber, &fiber_attr);

	struct coro_impl *impl = fiber_attr.data_addr;
	assert(impl);

	impl->fiber = fiber;
	impl->sched = coro_thrd_get_sched();

	if (!coro_impl_init(impl, attr, func, arg)) {
		errc = get_errc();
		goto error_init_impl;
	}

	impl->attr.stack_size = fiber_attr.stack_size;
#if !_WIN32
	impl->attr.stack_addr = fiber_attr.stack_addr;
#endif

	*coro = &impl->coro;

	coro_resume(*coro);

	return coro_success;

	// coro_impl_fini(impl);
error_init_impl:
	fiber_destroy(fiber);
error_create_fiber:
	set_errc(errc);
	*coro = NULL;
	return errc2num(errc) == ERRNUM_NOMEM ? coro_nomem : coro_error;
}
void
coro_get_attr(coro_t coro, struct coro_attr *pattr)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

	if (pattr)
		*pattr = impl->attr;
}

coro_t
coro_current(void)
{
	assert(coro_thrd.curr);

	return &coro_thrd.curr->coro;
}

int
coro_equal(coro_t coro0, coro_t coro1)
{
	return coro0 == coro1;
}

int
coro_join(coro_t coro, int *res)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

	if (coro_equal(coro, coro_current())) {
		set_errnum(ERRNUM_DEADLK);
		return coro_error;
	}

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif

	if (impl->detached || impl->joined) {
		set_errnum(ERRNUM_INVAL);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return coro_error;
	}

	if (!impl->stopped) {
		impl->joined = coro_impl_from_coro(coro_current());
#if LELY_NO_THREADS
		coro_suspend();
#else
		// Unlock the mutex after the coroutine is suspended. This
		// prevents a race condition where the coroutine is resumed on
		// another thread before it is suspended.
		coro_suspend_with(&coro_join_suspend_func_l, impl);
#endif
	}

	if (res)
		*res = impl->res;

	coro_impl_destroy(impl);

	return coro_success;
}

int
coro_detach(coro_t coro)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif

	if (impl->detached || impl->joined) {
		set_errnum(ERRNUM_INVAL);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return coro_error;
	}

	if (impl->stopped) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_impl_destroy(impl);
	} else {
		impl->detached = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
	}

	return coro_success;
}

_Noreturn void
coro_exit(int res)
{
	struct coro_thrd *thr = &coro_thrd;

	if (thr->curr && thr->curr != &thr->main) {
		thr->curr->res = res;
		// Suspend the coroutine before destroying it.
		coro_suspend_with(&coro_exit_suspend_func, NULL);
	}

#if LELY_NO_THREADS
	exit(res);
#else
	thrd_exit(res);
#endif
}

void
coro_yield(void)
{
	coro_suspend_with(&coro_yield_suspend_func, NULL);
}

int
coro_sleep(const struct timespec *duration, struct timespec *remaining)
{
	assert(duration);

	struct timespec timeout = { 0, 0 };
	if (!timespec_get(&timeout, TIME_UTC)) {
		if (remaining)
			*remaining = *duration;
		return -2;
	}
	timespec_add(&timeout, duration);

	struct coro_thrd_wait wait = { .func = &coro_sleep_wait_func,
		.arg = coro_current(),
		.thr = &coro_thrd };
	pnode_init(&wait.node, &timeout);

	coro_suspend_with(&coro_sleep_suspend_func, &wait);

	if (remaining)
		*remaining = (struct timespec){ 0, 0 };

	return 0;
}

void
coro_suspend(void)
{
	coro_suspend_with(NULL, NULL);
}

void
coro_suspend_with(void (*func)(coro_t coro, void *arg), void *arg)
{
	struct coro_thrd *thr = &coro_thrd;
	assert(thr->curr);
	coro_t coro = &thr->curr->coro;

	coro_t next = coro_sched_pop(coro_thrd_get_sched());
	thr->curr = next ? coro_impl_from_coro(next) : NULL;

	fiber_t *fiber = thr->curr ? thr->curr->fiber : thr->fiber;
	struct {
		void (*func)(coro_t coro, void *arg);
		coro_t coro;
		void *arg;
		struct coro_thrd *thr;
	} args = { func, coro, arg, thr };
	fiber_resume_with(fiber, &coro_suspend_with_fiber_func, &args);
}

void
coro_resume(coro_t coro)
{
	coro_sched_t *sched = coro_get_sched(coro);
	coro_sched_push(sched, coro);
#if LELY_NO_THREADS
	assert(sched == coro_thrd.main.sched);
#else
	if (sched != coro_thrd.main.sched)
		coro_sched_signal(sched);
#endif
}

coro_sched_t *
coro_get_sched(coro_t coro)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

	return impl->sched;
}

int
coro_set_sched(coro_t coro, coro_sched_t *sched)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

	if (sched != impl->sched && coro_is_pinned(coro))
		return coro_error;
	assert(impl->fiber);

	impl->sched = sched;

	return coro_success;
}

int
coro_is_pinned(coro_t coro)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);

	return impl->attr.pinned;
}

static inline struct coro_impl *
coro_impl_from_coro(coro_t coro)
{
	assert(coro);

	return structof(coro, struct coro_impl, coro);
}

static fiber_t *
coro_impl_fiber_func_l(fiber_t *fiber, void *arg)
{
	struct coro_impl *impl = fiber_data(fiber);
	assert(impl);
	assert(impl->func);
	(void)arg;

#if !LELY_NO_THREADS
	mtx_unlock(&coro_thrd.mtx);
#endif

	coro_exit(impl->func(impl->arg));

	return NULL;
}

static struct coro_impl *
coro_impl_init(struct coro_impl *impl, const struct coro_attr *attr,
		coro_start_t func, void *arg)
{
	assert(impl);
	assert(attr);

	impl->attr = *attr;

	impl->func = func;
	impl->arg = arg;
	impl->res = 0;

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success)
		return NULL;
#endif

	impl->stopped = 0;
	impl->detached = 0;
	impl->joined = NULL;

	return impl;
}

static void
coro_impl_fini(struct coro_impl *impl)
{
#if LELY_NO_THREADS
	(void)impl;
#else
	assert(impl);

	mtx_destroy(&impl->mtx);
#endif
}

static void
coro_impl_destroy(struct coro_impl *impl)
{
	assert(impl);
	assert(impl != &coro_thrd.main);

	if (impl) {
		coro_impl_fini(impl);
		fiber_destroy(impl->fiber);
	}
}

static fiber_t *
coro_thrd_fiber_func_l(fiber_t *fiber, void *arg)
{
	(void)fiber;
	struct coro_thrd *thr = arg;
	assert(thr);
	coro_sched_t *sched = coro_thrd_get_sched();

	for (;;) {
		assert(!thr->curr);
		coro_t coro = coro_sched_pop(sched);
		if (coro) {
			thr->curr = coro_impl_from_coro(coro);
			fiber_resume(thr->curr->fiber);
		} else {
#if !LELY_NO_THREADS
			mtx_lock(&thr->mtx);
#endif
			struct pnode *node = pheap_first(&thr->heap);
			if (node) {
				// Copy the timeout in case the waiting function
				// is canceled by another thread.
				const struct timespec *ts = node->key;
				struct timespec timeout = *ts;
#if !LELY_NO_THREADS
				mtx_unlock(&thr->mtx);
#endif
				coro_sched_wait(sched, &timeout);
			} else {
#if !LELY_NO_THREADS
				mtx_unlock(&thr->mtx);
#endif
				coro_sched_wait(sched, NULL);
			}
			coro_thrd_wake(thr);
		}
	}

	return NULL;
}

static void
coro_thrd_wake(struct coro_thrd *thr)
{
	assert(thr);

#if !LELY_NO_THREADS
	mtx_lock(&thr->mtx);
#endif

	if (pheap_empty(&thr->heap)) {
#if !LELY_NO_THREADS
		mtx_unlock(&thr->mtx);
#endif
		return;
	}

	struct timespec now = { 0, 0 };
	int errc = get_errc();
	if (!timespec_get(&now, TIME_UTC)) {
#if !LELY_NO_THREADS
		mtx_unlock(&thr->mtx);
#endif
		set_errc(errc);
		return;
	}

	struct pnode *node;
	while ((node = pheap_first(&thr->heap))) {
		if (timespec_cmp(&now, node->key) < 0)
			break;
		pheap_remove(&thr->heap, node);

		struct coro_thrd_wait *wait =
				structof(node, struct coro_thrd_wait, node);
		assert(wait->func);
		wait->func(wait->arg);
	}

#if !LELY_NO_THREADS
	mtx_unlock(&thr->mtx);
#endif
}

static fiber_t *
coro_suspend_with_fiber_func(fiber_t *fiber, void *arg)
{
	(void)fiber;
	struct {
		void (*func)(coro_t coro, void *arg);
		coro_t coro;
		void *arg;
		struct coro_thrd *thr;
	} *args = arg;
	assert(args);
	struct coro_thrd *thr = args->thr;
	assert(thr);

	if (args->func)
		args->func(args->coro, args->arg);

	coro_thrd_wake(thr);

	return NULL;
}

#if !LELY_NO_THREADS
static void
coro_join_suspend_func_l(coro_t coro, void *arg)
{
	(void)coro;
	struct coro_impl *impl = arg;
	assert(impl);

	mtx_unlock(&impl->mtx);
}
#endif

static void
coro_exit_suspend_func(coro_t coro, void *arg)
{
	struct coro_impl *impl = coro_impl_from_coro(coro);
	(void)arg;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	assert(!impl->stopped);
	impl->stopped = 1;

	if (impl->detached) {
		assert(!impl->joined);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_impl_destroy(impl);
	} else if (impl->joined) {
		assert(impl->joined != impl);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_resume(&impl->joined->coro);
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}
}

static void
coro_yield_suspend_func(coro_t coro, void *arg)
{
	(void)arg;

	coro_resume(coro);
}

static void
coro_sleep_suspend_func(coro_t coro, void *arg)
{
	(void)coro;
	struct coro_thrd_wait *wait = arg;
	assert(wait);
	struct coro_thrd *thr = wait->thr;
	assert(thr);

#if !LELY_NO_THREADS
	mtx_lock(&thr->mtx);
#endif
	pheap_insert(&thr->heap, &wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&thr->mtx);
#endif
}

static void
coro_sleep_wait_func(void *arg)
{
	coro_t coro = arg;
	assert(coro);

	coro_resume(coro);
}
