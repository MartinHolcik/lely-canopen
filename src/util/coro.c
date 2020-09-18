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
#include <lely/util/cmp.h>
#include <lely/util/coro.h>
#include <lely/util/coro_sched.h>
#include <lely/util/dllist.h>
#include <lely/util/errnum.h>
#include <lely/util/fiber.h>
#include <lely/util/pheap.h>
#include <lely/util/rbtree.h>
#include <lely/util/time.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdint.h>
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
	/**
	 * The tree containing all coroutine-specific storage values for this
	 * coroutine.
	 */
	struct rbtree tree;
};

static fiber_t *coro_impl_fiber_func_l(fiber_t *fiber, void *arg);

static inline struct coro_impl *coro_impl_from_coro(coro_t coro);

static struct coro_impl *coro_impl_init(struct coro_impl *impl,
		const struct coro_attr *attr, coro_start_t func, void *arg);
static void coro_impl_fini(struct coro_impl *impl);

static void coro_impl_destroy(struct coro_impl *impl);

/**
 * Runs the destructors for all coroutine-specific storage values owned by a
 * coroutine.
 */
static void coro_impl_css_dtor(struct coro_impl *impl);

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

/// The implementation of a coroutine mutex.
struct coro_mtx_impl {
	/// The type of mutex.
	int type;
#if !LELY_NO_THREADS
	/// The mutex protecting #locked, #coro and #queue.
	mtx_t mtx;
#endif
	/// The number of times the mutex has been recursively locked.
	size_t locked;
	/// The coroutine holding the lock.
	coro_t coro;
	/// The queue of coroutines waiting to acquire the lock.
	struct dllist queue;
};

static int coro_mtx_impl_trylock_l(struct coro_mtx_impl *impl);

/// An object representing a coroutine waiting to lock a mutex.
struct coro_mtx_wait {
	/// A pointer to the mutex.
	coro_mtx_t *mtx;
	/// The coroutine waiting to lock the mutex.
	coro_t coro;
	/// The node in the queue of the nutex.
	struct dlnode node;
};

static void coro_mtx_wait_lock(struct coro_mtx_wait *wait);

/// The implementation of a coroutine condition variable.
struct coro_cnd_impl {
#if !LELY_NO_THREADS
	/// The mutex protecting #queue.
	mtx_t mtx;
#endif
	/**
	 * The list of coroutines waiting for the condition variable to be
	 * signaled.
	 */
	struct dllist queue;
};

/**
 * An object representing a coroutine waiting for a condition variable to be
 * signaled.
 */
struct coro_cnd_wait {
	/// A pointer to the condition variable.
	coro_cnd_t *cond;
	/// A flag indicating whether the condition variable was signaled.
	int signaled;
	/**
	 * The object used when waiting to lock the mutex after the condition
	 * variable has been signaled.
	 */
	struct coro_mtx_wait mtx_wait;
	/// The node in the queue of the condition variable.
	struct dlnode node;
};

static void coro_mtx_lock_suspend_func_l(coro_t coro, void *arg);
static void coro_mtx_timedlock_suspend_func_l(coro_t coro, void *arg);
static void coro_mtx_timedlock_wait_func(void *arg);

static void coro_cnd_wait_suspend_func_l(coro_t coro, void *arg);
static void coro_cnd_timedwait_suspend_func_l(coro_t coro, void *arg);
static void coro_cnd_timedwait_wait_func(void *arg);

/// A coroutine-specific storage key.
struct css_key {
	/// The destructor coroutine-specific storage values bound to this key.
	css_dtor_t dtor;
#if !LELY_NO_THREADS
	/// The mutex protecting #list.
	mtx_t mtx;
#endif
	/**
	 * The list containing all coroutine-specific storage values bound to
	 * this key.
	 */
	struct dllist list;
};

/// A coroutine-specific storage value.
struct css_val {
	/// A pointer to the value.
	void *val;
	/// A pointer to the coroutine owning this value.
	struct coro_impl *coro;
	/// The node of this value in the tree of *#coro.
	struct rbnode rbnode;
	/// The node of this value in the list of the key.
	struct dlnode dlnode;
};

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
		coro_impl_css_dtor(thr->curr);

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

		coro_impl_css_dtor(thr->curr);

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

int
coro_mtx_init(coro_mtx_t *mtx, int type)
{
	assert(mtx);

	if (type & ~(coro_mtx_timed | coro_mtx_recursive)) {
		set_errnum(ERRNUM_INVAL);
		return coro_error;
	}

	struct coro_mtx_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return coro_nomem;
	}

	impl->type = type;

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success) {
		free(impl);
		return coro_error;
	}
#endif

	impl->locked = 0;
	impl->coro = NULL;
	dllist_init(&impl->queue);

	mtx->_impl = impl;

	return coro_success;
}

void
coro_mtx_destroy(coro_mtx_t *mtx)
{
	if (mtx && mtx->_impl) {
		struct coro_mtx_impl *impl = mtx->_impl;
		mtx->_impl = NULL;

		assert(!impl->locked);
		assert(dllist_empty(&impl->queue));
#if !LELY_NO_THREADS
		mtx_destroy(&impl->mtx);
#endif
		free(impl);
	}
}

int
coro_mtx_lock(coro_mtx_t *mtx)
{
	assert(mtx);
	struct coro_mtx_impl *impl = mtx->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (!impl->locked || coro_equal(impl->coro, coro_current())) {
		int result = coro_mtx_impl_trylock_l(impl);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return result;
	}

	struct coro_mtx_wait wait = { .mtx = mtx };
	// impl->mtx is unlocked by coro_mtx_lock_suspend_func_l().
	coro_suspend_with(&coro_mtx_lock_suspend_func_l, &wait);

	return coro_success;
}

int
coro_mtx_trylock(coro_mtx_t *mtx)
{
	assert(mtx);
	struct coro_mtx_impl *impl = mtx->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	int result = coro_mtx_impl_trylock_l(impl);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
	return result;
}

int
coro_mtx_timedlock(coro_mtx_t *mtx, const struct timespec *ts)
{
	struct coro_thrd *thr = &coro_thrd;
	assert(mtx);
	struct coro_mtx_impl *impl = mtx->_impl;
	assert(impl);
	assert(ts);

	if (ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000l) {
		set_errnum(ERRNUM_INVAL);
		return coro_error;
	}

	if (!(impl->type & coro_mtx_timed)) {
		set_errnum(ERRNUM_PERM);
		return coro_error;
	}

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (!impl->locked || coro_equal(impl->coro, coro_current())) {
		int result = coro_mtx_impl_trylock_l(impl);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return result;
	}

	struct coro_mtx_wait mtx_wait = { .mtx = mtx };
	struct coro_mtx_wait *waiting = &mtx_wait;
	struct coro_thrd_wait thrd_wait = {
		.func = &coro_mtx_timedlock_wait_func,
		.arg = &waiting,
		.thr = thr
	};
	pnode_init(&thrd_wait.node, ts);

	struct {
		struct coro_mtx_wait *mtx_wait;
		struct coro_thrd_wait *thrd_wait;
	} args = { &mtx_wait, &thrd_wait };
	// impl->mtx is unlocked by coro_mtx_timedlock_suspend_func_l().
	coro_suspend_with(&coro_mtx_timedlock_suspend_func_l, &args);
	thr = thrd_wait.thr;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (coro_equal(impl->coro, mtx_wait.coro)) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
		mtx_lock(&thr->mtx);
#endif
		// Check if we need to deregister the waiting function. We may
		// not if the waiting function was executed between locking the
		// mutex and resuming the coroutine.
		if (waiting)
			pheap_remove(&thr->heap, &thrd_wait.node);
#if !LELY_NO_THREADS
		mtx_unlock(&thr->mtx);
#endif
		return coro_success;
	} else {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		// A timeout can only occur if the waiting fuction was executed.
		assert(!waiting);
		return coro_timedout;
	}
}

int
coro_mtx_unlock(coro_mtx_t *mtx)
{
	assert(mtx);
	struct coro_mtx_impl *impl = mtx->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (!impl->locked || !coro_equal(impl->coro, coro_current())) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		set_errnum(ERRNUM_PERM);
		return coro_error;
	}

	if (!--impl->locked) {
		impl->coro = NULL;
		// Check if another coroutine is waiting to lock the mutex. If
		// so, lock the mutex and resume that coroutine.
		struct dlnode *node = dllist_pop_front(&impl->queue);
		if (node) {
			struct coro_mtx_wait *wait = structof(
					node, struct coro_mtx_wait, node);
			impl->locked++;
			impl->coro = wait->coro;
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
#endif
			coro_resume(impl->coro);
#if !LELY_NO_THREADS
		} else {
			mtx_unlock(&impl->mtx);
#endif
		}
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}

	return coro_success;
}

int
coro_cnd_init(coro_cnd_t *cond)
{
	assert(cond);

	struct coro_cnd_impl *impl = malloc(sizeof(*impl));
	if (!impl) {
		set_errc(errno2c(errno));
		return coro_nomem;
	}

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success) {
		free(impl);
		return coro_error;
	}
#endif

	dllist_init(&impl->queue);

	cond->_impl = impl;

	return coro_success;
}

void
coro_cnd_destroy(coro_cnd_t *cond)
{
	if (cond && cond->_impl) {
		struct coro_cnd_impl *impl = cond->_impl;
		cond->_impl = NULL;

		assert(dllist_empty(&impl->queue));
#if !LELY_NO_THREADS
		mtx_destroy(&impl->mtx);
#endif
		free(impl);
	}
}

int
coro_cnd_signal(coro_cnd_t *cond)
{
	assert(cond);
	struct coro_cnd_impl *impl = cond->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct dlnode *node = dllist_pop_front(&impl->queue);
	if (node) {
		struct coro_cnd_wait *wait =
				structof(node, struct coro_cnd_wait, node);
		wait->signaled = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_mtx_wait_lock(&wait->mtx_wait);
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}

	return coro_success;
}

int
coro_cnd_broadcast(coro_cnd_t *cond)
{
	assert(cond);
	struct coro_cnd_impl *impl = cond->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct dlnode *node;
	while ((node = dllist_pop_front(&impl->queue))) {
		struct coro_cnd_wait *wait =
				structof(node, struct coro_cnd_wait, node);
		wait->signaled = 1;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_mtx_wait_lock(&wait->mtx_wait);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif

	return coro_success;
}

int
coro_cnd_wait(coro_cnd_t *cond, coro_mtx_t *mtx)
{
	assert(cond);
	struct coro_cnd_impl *impl = cond->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (coro_mtx_unlock(mtx) != coro_success) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return coro_error;
	}

	struct coro_cnd_wait wait = { .cond = cond,
		.mtx_wait = { .mtx = mtx } };
	struct {
		struct coro_cnd_impl *impl;
		struct coro_cnd_wait *wait;
	} args = { impl, &wait };
	// impl->mtx is unlocked by coro_cnd_wait_suspend_func_l().
	coro_suspend_with(&coro_cnd_wait_suspend_func_l, &args);

	return coro_success;
}

int
coro_cnd_timedwait(coro_cnd_t *cond, coro_mtx_t *mtx, const struct timespec *ts)
{
	struct coro_thrd *thr = &coro_thrd;
	assert(cond);
	struct coro_cnd_impl *impl = cond->_impl;
	assert(impl);
	assert(ts);

	if (ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000l) {
		set_errnum(ERRNUM_INVAL);
		return coro_error;
	}

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (coro_mtx_unlock(mtx) != coro_success) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		return coro_error;
	}

	struct coro_cnd_wait cond_wait = { .cond = cond,
		.mtx_wait = { .mtx = mtx } };
	struct coro_cnd_wait *waiting = &cond_wait;
	struct coro_thrd_wait thrd_wait = {
		.func = &coro_cnd_timedwait_wait_func,
		.arg = &waiting,
		.thr = thr
	};
	pnode_init(&thrd_wait.node, ts);

	struct {
		struct coro_cnd_impl *impl;
		struct coro_cnd_wait *cond_wait;
		struct coro_thrd_wait *thrd_wait;
	} args = { impl, &cond_wait, &thrd_wait };
	// impl->mtx is unlocked by coro_cnd_timedwait_suspend_func_l().
	coro_suspend_with(&coro_cnd_timedwait_suspend_func_l, &args);
	thr = thrd_wait.thr;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (cond_wait.signaled) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
		mtx_lock(&thr->mtx);
#endif
		// Check if we need to deregister the waiting function. We may
		// not if the waiting function was executed between signaling
		// the condition variable and resuming the coroutine.
		if (waiting)
			pheap_remove(&thr->heap, &thrd_wait.node);
#if !LELY_NO_THREADS
		mtx_unlock(&thr->mtx);
#endif
		return coro_success;
	} else {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		// A timeout can only occur if the waiting fuction was executed.
		assert(!waiting);
		return coro_timedout;
	}
}

int
css_create(css_t *key, css_dtor_t dtor)
{
	assert(key);

	int errc = 0;

	struct css_key *impl = malloc(sizeof(*impl));
	if (!impl) {
		errc = errno2c(errno);
		goto error_malloc_impl;
	}

	impl->dtor = dtor;

#if !LELY_NO_THREADS
	if (mtx_init(&impl->mtx, mtx_plain) != thrd_success) {
		errc = get_errc();
		goto error_init_mtx;
	}
#endif
	dllist_init(&impl->list);

	*key = impl;

	return coro_success;

#if !LELY_NO_THREADS
	// mtx_destroy(&impl->mtx);
error_init_mtx:
#endif
	free(impl);
error_malloc_impl:
	set_errc(errc);
	*key = NULL;
	return coro_error;
}

void
css_delete(css_t key)
{
	struct css_key *key_impl = key;
	assert(key_impl);

	// Remove the values from the coroutines. We do not need to lock the
	// mutex, since it is undefined behavior to use the key after this
	// function has been called.
	struct dlnode *dlnode;
	while ((dlnode = dllist_pop_front(&key_impl->list))) {
		struct css_val *val_impl =
				structof(dlnode, struct css_val, dlnode);
		assert(val_impl->coro);
#if !LELY_NO_THREADS
		mtx_lock(&val_impl->coro->mtx);
#endif
		rbtree_remove(&val_impl->coro->tree, &val_impl->rbnode);
#if !LELY_NO_THREADS
		mtx_unlock(&val_impl->coro->mtx);
#endif
	}

#if !LELY_NO_THREADS
	mtx_destroy(&key_impl->mtx);
#endif
	free(key_impl);
}

void *
css_get(css_t key)
{
	struct coro_impl *impl = coro_impl_from_coro(coro_current());

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct rbnode *rbnode = rbtree_find(&impl->tree, key);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
	return rbnode ? structof(rbnode, struct css_val, rbnode)->val : NULL;
}

int
css_set(css_t key, void *val)
{
	struct coro_impl *impl = coro_impl_from_coro(coro_current());
	struct css_key *key_impl = key;
	assert(key_impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct rbnode *rbnode = rbtree_find(&impl->tree, key);
	if (rbnode) {
		struct css_val *val_impl =
				structof(rbnode, struct css_val, rbnode);
		if (val) {
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
#endif
			val_impl->val = val;
		} else {
			rbtree_remove(&impl->tree, rbnode);
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
			mtx_lock(&key_impl->mtx);
#endif
			dllist_remove(&key_impl->list, &val_impl->dlnode);
#if !LELY_NO_THREADS
			mtx_unlock(&key_impl->mtx);
#endif
			free(val_impl);
		}
	} else if (val) {
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		struct css_val *val_impl = malloc(sizeof(*val_impl));
		if (!val_impl) {
			set_errc(errno2c(errno));
			return coro_nomem;
		}
		val_impl->val = val;
		val_impl->coro = impl;
		rbnode_init(&val_impl->rbnode, key);
		dlnode_init(&val_impl->dlnode);
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
		rbtree_insert(&impl->tree, &val_impl->rbnode);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
		mtx_lock(&key_impl->mtx);
#endif
		dllist_push_back(&key_impl->list, &val_impl->dlnode);
#if !LELY_NO_THREADS
		mtx_unlock(&key_impl->mtx);
#endif
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}

	return coro_success;
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

	rbtree_init(&impl->tree, &ptr_cmp);

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

static void
coro_impl_css_dtor(struct coro_impl *impl)
{
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	struct rbnode *rbnode;
	while ((rbnode = rbtree_root(&impl->tree))) {
		rbtree_remove(&impl->tree, rbnode);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		struct css_key *key_impl = (css_t)rbnode->key;
		struct css_val *val_impl =
				structof(rbnode, struct css_val, rbnode);
#if !LELY_NO_THREADS
		mtx_lock(&key_impl->mtx);
#endif
		dllist_remove(&key_impl->list, &val_impl->dlnode);
#if !LELY_NO_THREADS
		mtx_unlock(&key_impl->mtx);
#endif
		css_dtor_t dtor = key_impl->dtor;
		void *val = val_impl->val;
		free(val_impl);
		if (dtor) {
			assert(val);
			dtor(val);
		}
#if !LELY_NO_THREADS
		mtx_lock(&impl->mtx);
#endif
	}
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
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

static int
coro_mtx_impl_trylock_l(struct coro_mtx_impl *impl)
{
	assert(impl);

	if (impl->locked) {
		if (coro_equal(impl->coro, coro_current())) {
			if (!(impl->type & coro_mtx_recursive)) {
				set_errnum(ERRNUM_DEADLK);
				return coro_error;
			} else if (impl->locked >= SIZE_MAX) {
				set_errnum(ERRNUM_AGAIN);
				return coro_error;
			}
			impl->locked++;
			return coro_success;
		} else {
			return coro_busy;
		}
	} else {
		assert(!impl->coro);
		assert(dllist_empty(&impl->queue));
		impl->locked = 1;
		impl->coro = coro_current();
		return coro_success;
	}
}

static void
coro_mtx_wait_lock(struct coro_mtx_wait *wait)
{
	assert(wait);
	assert(wait->mtx);
	assert(wait->coro);
	struct coro_mtx_impl *impl = wait->mtx->_impl;
	assert(impl);

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	if (impl->locked) {
		if (coro_equal(impl->coro, wait->coro)) {
			assert(impl->type & coro_mtx_recursive);
			assert(impl->locked < SIZE_MAX);
			impl->locked++;
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
#endif
			coro_resume(impl->coro);
		} else {
			dllist_push_back(&impl->queue, &wait->node);
#if !LELY_NO_THREADS
			mtx_unlock(&impl->mtx);
#endif
		}
	} else {
		assert(dllist_empty(&impl->queue));
		impl->locked = 1;
		impl->coro = wait->coro;
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_resume(impl->coro);
	}
}

static void
coro_mtx_lock_suspend_func_l(coro_t coro, void *arg)
{
	assert(coro);
	struct coro_mtx_wait *wait = arg;
	assert(wait);
	assert(wait->mtx);
	struct coro_mtx_impl *impl = wait->mtx->_impl;
	assert(impl);

	wait->coro = coro;
	dllist_push_back(&impl->queue, &wait->node);

#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
}

static void
coro_mtx_timedlock_suspend_func_l(coro_t coro, void *arg)
{
	assert(coro);
	struct {
		struct coro_mtx_wait *mtx_wait;
		struct coro_thrd_wait *thrd_wait;
	} *args = arg;
	assert(args);
	struct coro_mtx_wait *mtx_wait = args->mtx_wait;
	assert(mtx_wait);
	assert(mtx_wait->mtx);
	struct coro_mtx_impl *impl = mtx_wait->mtx->_impl;
	assert(impl);
	struct coro_thrd_wait *thrd_wait = args->thrd_wait;
	assert(thrd_wait);
	struct coro_thrd *thr = thrd_wait->thr;
	assert(thr);

	mtx_wait->coro = coro;
	dllist_push_back(&impl->queue, &mtx_wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);

	mtx_lock(&thr->mtx);
#endif
	pheap_insert(&thr->heap, &thrd_wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&thr->mtx);
#endif
}

static void
coro_mtx_timedlock_wait_func(void *arg)
{
	struct coro_mtx_wait **pwaiting = arg;
	assert(arg);
	struct coro_mtx_wait *wait = *pwaiting;
	assert(wait);
	assert(wait->mtx);
	struct coro_mtx_impl *impl = wait->mtx->_impl;
	assert(impl);

	*pwaiting = NULL;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Check if we succeeded in locking the mutex. If not, deregister the
	// coroutine and resume it.
	if (!coro_equal(impl->coro, wait->coro)) {
		dllist_remove(&impl->queue, &wait->node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_resume(wait->coro);
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}
}

static void
coro_cnd_wait_suspend_func_l(coro_t coro, void *arg)
{
	assert(coro);
	struct {
		struct coro_cnd_impl *impl;
		struct coro_cnd_wait *wait;
	} *args = arg;
	assert(args);
	struct coro_cnd_impl *impl = args->impl;
	assert(impl);
	struct coro_cnd_wait *wait = args->wait;
	assert(wait);

	wait->mtx_wait.coro = coro;
	dllist_push_back(&impl->queue, &wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);
#endif
}

static void
coro_cnd_timedwait_suspend_func_l(coro_t coro, void *arg)
{
	assert(coro);
	struct {
		struct coro_cnd_impl *impl;
		struct coro_cnd_wait *cond_wait;
		struct coro_thrd_wait *thrd_wait;
	} *args = arg;
	assert(args);
	struct coro_cnd_impl *impl = args->impl;
	assert(impl);
	struct coro_cnd_wait *cond_wait = args->cond_wait;
	assert(cond_wait);
	struct coro_thrd_wait *thrd_wait = args->thrd_wait;
	assert(thrd_wait);
	struct coro_thrd *thr = thrd_wait->thr;
	assert(thr);

	cond_wait->mtx_wait.coro = coro;
	dllist_push_back(&impl->queue, &cond_wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&impl->mtx);

	mtx_lock(&thr->mtx);
#endif
	pheap_insert(&thr->heap, &thrd_wait->node);
#if !LELY_NO_THREADS
	mtx_unlock(&thr->mtx);
#endif
}

static void
coro_cnd_timedwait_wait_func(void *arg)
{
	struct coro_cnd_wait **pwaiting = arg;
	assert(pwaiting);
	struct coro_cnd_wait *wait = *pwaiting;
	assert(wait);
	assert(wait->cond);
	struct coro_cnd_impl *impl = wait->cond->_impl;
	assert(impl);

	*pwaiting = NULL;

#if !LELY_NO_THREADS
	mtx_lock(&impl->mtx);
#endif
	// Check if the condition variable was signaled. If not, deregister the
	// coroutine and lock the mutex.
	if (!wait->signaled) {
		dllist_remove(&impl->queue, &wait->node);
#if !LELY_NO_THREADS
		mtx_unlock(&impl->mtx);
#endif
		coro_mtx_wait_lock(&wait->mtx_wait);
#if !LELY_NO_THREADS
	} else {
		mtx_unlock(&impl->mtx);
#endif
	}
}
