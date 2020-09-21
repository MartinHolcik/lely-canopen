/**@file
 * This header file is part of the utilities library; it contains the asymmetric
 * coroutine declarations.
 *
 * The asymmetric coroutine API is based on the C11 threads API; it follows the
 * syntax and semantics of the functions in `<threads.h>` as much as possible.
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

#ifndef LELY_UTIL_CORO_H_
#define LELY_UTIL_CORO_H_

#include <lely/libc/time.h>

#include <stddef.h>

enum {
	/// Indicates that the requested operation succeeded.
	coro_success,
	/// Indicates that the requested operation failed.
	coro_error,
	/**
	 * Indicates that the time specified in the call was reached without
	 * acquiring the requested resource.
	 */
	coro_timedout,
	/**
	 * Indicates that the requested operation failed because a resource
	 * requested by a test and return function is already in use.
	 */
	coro_busy,
	/**
	 * Indicates that the requested operation failed because it was unable
	 * to allocate memory.
	 */
	coro_nomem
};

/// Coroutine attributes.
struct coro_attr {
	/// A flag specifying whether a coroutine is pinned to a thread.
	unsigned pinned : 1;
	/**
	 * A flag specifying a coroutine to save and restore the signal mask
	 * (only supported on POSIX platforms).
	 */
	unsigned save_mask : 1;
	/**
	 * A flag specifying a coroutine to save and restore the floating-point
	 * environment.
	 */
	unsigned save_fenv : 1;
	/**
	 * A flag specifying a coroutine to save and restore the error values
	 * (i.e., errno and GetLastError() on Windows).
	 */
	unsigned save_error : 1;
	/**
	 * A flag specifying a coroutine to add a guard page when allocating the
	 * stack frame so that the kernel generates a SIGSEGV signal on stack
	 * overflow (only supported on those POSIX platforms where mmap()
	 * supports anonymous mappings). This flag cannot be used with a
	 * pre-allocated stack.
	 */
	unsigned guard_stack : 1;
	/**
	 * The size (in bytes) of the stack frame of a coroutine. If #stack_addr
	 * is NULL, a stack frame will be allocated on coroutine creation. The
	 * size of the allocated stack is always at least #LELY_CORO_MINSTKSZ
	 * bytes. If <b>stack_size</b> is 0, the default size (#LELY_CORO_STKSZ)
	 * is used.
	 */
	size_t stack_size;
#if !_WIN32
	/**
	 * A pointer to the first byte of a memory region to be used as the
	 * stack frame for a coroutine. If NULL, a stack frame will be allocated
	 * on coroutine creation. If not NULL, it is the responsibility of the
	 * caller to ensure proper alignment.
	 */
	void *stack_addr;
#endif
};

/// The static initializer for #coro_attr.
#if _WIN32
#define CORO_ATTR_INIT \
	{ \
		0, 0, 0, 0, 0, 0 \
	}
#else
#define CORO_ATTR_INIT \
	{ \
		0, 0, 0, 0, 0, 0, NULL \
	}
#endif

/// A complete object type that holds an identifier for a coroutine.
typedef struct coro *coro_t;

/// An abstract coroutine scheduler factory.
typedef const struct coro_sched_ctor_vtbl *const coro_sched_ctor_t;

/// An abstract coroutine scheduler.
typedef const struct coro_sched_vtbl *const coro_sched_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The function pointer type that is passed to coro_create() to create a new
 * coroutine.
 */
typedef int (*coro_start_t)(void *);

/**
 * Initializes the coroutine associated with the calling thread, as well as the
 * coroutine scheduler for the thread. This is necessary because coroutine
 * functions can only be called from within a valid coroutine. This function can
 * be invoked more than once by the same thread. Only the first invocation
 * initializes the coroutine.
 *
 * @param attr a pointer to the coroutine attributes. If <b>attr</b> is NULL,
 *             the default attributes are used. Attributes relating to the stack
 *             are ignored.
 * @param ctor a pointer to the factory used to create, and later destroy, the
 *             coroutine scheduler for the calling thread. If <b>ctor</b> is
 *             NULL, a default (round-robin) scheduler is used.
 *
 * @returns 1 if a coroutine already is associated with the calling thread, 0 if
 * it has been successfully initialized, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 *
 * @see coro_thrd_fini()
 */
int coro_thrd_init(const struct coro_attr *attr, coro_sched_ctor_t *ctor);

/**
 * Finalizes the coroutine associated with the calling thread, as well as the
 * coroutine scheduler for the thread. This function MUST be called once for
 * each successful call to coro_thrd_init(). Only the last invocation finalizes
 * the coroutine.
 *
 * @see coro_thrd_init()
 */
void coro_thrd_fini(void);

/**
 * Returns a pointer to the coroutine scheduler for the calling thread.
 *
 * @see coro_thrd_init().
 */
coro_sched_t *coro_thrd_get_sched(void);

/**
 * Creates a new coroutine executing `func(arg)`. On success, the newly created
 * coroutine is scheduled for execution on the calling thread.
 *
 * @param coro the address at which to store the identifier of the newly created
 *             coroutine.
 * @param attr a pointer to the attributes to be used when creating the
 *             coroutine. If NULL, the attributes are inherited from the
 *             currently executing coroutine.
 * @param func the function to be executed in the coroutine. If the function
 *             returns, the coroutine is exited as if by coro_exit().
 * @param arg  the argument to <b>func</b>.
 *
 * @returns #coro_success on success, #coro_nomem if no memory could be
 * allocated for the coroutine requested, or #coro_error if the request could
 * not be honored.
 */
int coro_create(coro_t *coro, const struct coro_attr *attr, coro_start_t func,
		void *arg);

/**
 * Copies the attributes of the coroutine identified by <b>coro</b> to
 * <b>pattr</b>.
 *
 * @see coro_get_priority()
 */
void coro_get_attr(coro_t coro, struct coro_attr *pattr);

/**
 * Identifies the coroutine that called it.
 *
 * @returns the identifier of the coroutine that called it.
 */
coro_t coro_current(void);

/**
 * Determines whether the coroutine identified by <b>coro0</b> refers to the
 * coroutine identified by <b>coro1</b>.
 *
 * @returns zero if the coroutine <b>coro0</b> and the coroutine <b>coro1</b>
 * refer to different coroutines. Otherwise this function returns a nonzero
 * value.
 */
int coro_equal(coro_t coro0, coro_t coro1);

/**
 * Joins the coroutine identified by <b>coro</b> with the current coroutine by
 * blocking until the other coroutine has terminated. If the parameter
 * <b>res</b> is not a NULL pointer, it stores the coroutine's result code in
 * the integer at <b>res</b>.
 *
 * @returns #coro_success on success, #coro_error if the coroutine was
 * previously detached or joined with another coroutine, or if a deadlock would
 * occur.
 *
 * @see coro_detach()
 */
int coro_join(coro_t coro, int *res);

/**
 * Detaches the coroutine identified by <b>coro</b> such that any resources
 * allocated to it are disposed when the coroutine terminates.
 *
 * @returns #coro_success on success, or #coro_error if the coroutine was
 * previously detached or joined with another coroutine.
 *
 * @see coro_join()
 */
int coro_detach(coro_t coro);

/**
 * Terminates execution of the calling coroutine and sets its result code to
 * <b>res</b>.
 *
 * If the coroutine associated with the calling thread is terminated, or if a
 * deadlock would occur, the calling thread is terminated as if by
 * `thrd_exit(res)`.
 */
_Noreturn void coro_exit(int res);

/// Suspends and reschedules the calling coroutine.
void coro_yield(void);

/**
 * Suspends execution of the calling coroutine until the interval specified by
 * <b>duration</b> has elapsed. If the <b>remaining</b> argument is not NULL,
 * the amount of time remaining (the requested interval minus the time actually
 * slept) is stored in the interval it points to. Because this function cannot
 * be interrupted, the amount of time remaining is always zero. The
 * <b>duration</b> and <b>remaining</b> arguments may point to the same object.
 *
 * The suspension time may be longer than requested because the interval is
 * rounded up to an integer multiple of the sleep resolution or because of the
 * scheduling of other activity by the system. But, except for the case of being
 * interrupted, the suspension time shall not be less than that specified, as
 * measured by the system clock TIME_UTC.
 *
 * @returns zero if the requested time has elapsed, or a negative value (less
 * than -1) if it fails.
 */
int coro_sleep(const struct timespec *duration, struct timespec *remaining);

/**
 * Suspends, but does not reschedule, the calling coroutine.
 *
 * @see coro_suspend_with(), coro_resume()
 */
void coro_suspend(void);

/**
 * Suspends, but does not reschedule, the calling coroutine. If <b>func</b> is
 * not NULL, `func(coro, arg)` is executed in the context of the next available
 * coroutine on the calling thread, right before it resumes, where <b>coro</b>
 * identifies the now suspended coroutine.
 *
 * It is safe to resume <b>coro</b> from <b>func</b> with coro_resume(), or to
 * change its scheduler with coro_set_sched().
 *
 * @see coro_suspend(), coro_resume()
 */
void coro_suspend_with(void (*func)(coro_t coro, void *arg), void *arg);

/**
 * Schedules the suspended coroutine identified by <b>coro</b> for execution.
 * The coroutine MUST NOT be running or already scheduled for execution.
 *
 * @see coro_suspend(), coro_suspend_with()
 */
void coro_resume(coro_t coro);

/**
 * Returns a pointer to the scheduler managing the coroutine identified by
 * <b>coro</b>.
 *
 * This function is not thread-safe.
 *
 * @see coro_set_sched()
 */
coro_sched_t *coro_get_sched(coro_t coro);

/**
 * Sets the scheduler for the coroutine identified by <b>coro</b> to
 * <b>sched</b>.
 *
 * This function is not thread-safe. IT MUST NOT be called while the coroutine
 * is running on another thread or while it is scheduled for execution with its
 * current scheduler.
 *
 * @returns #coro_success on success, or #coro_error if the coroutine is pinned
 * to its thread.
 *
 * @see coro_set_sched()
 */
int coro_set_sched(coro_t coro, coro_sched_t *sched);

/**
 * Returns 1 if the coroutine identified by <b>coro</b> is pinned to a thread,
 * and 0 if not.
 */
int coro_is_pinned(coro_t coro);

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_CORO_H_
