/**@file
 * This header file is part of the utilities library; it contains the fiber
 * declarations.
 *
 * <a href="https://en.wikipedia.org/wiki/Fiber_(computer_science)">Fibers</a>
 * are user-space threads. They provide cooperative multitasking and can be used
 * as a primitive for implementing stackful coroutines.
 *
 * The fiber implementation on Windows is based on CreateFiber()/SwitchToFiber()
 * and allows fibers to be migrated between threads. All other platforms use
 * mkjmp()/setjmp()/longjmp(). Since using longjmp() to restore an environment
 * saved by setjmp() in a different thread is undefined behavior (according to
 * 7.13.2.1), fibers can only be reliably resumed by the thread on which they
 * were created.
 *
 * @copyright 2018-2020 Lely Industries N.V.
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

#ifndef LELY_UTIL_FIBER_H_
#define LELY_UTIL_FIBER_H_

#include <lely/features.h>

#include <stddef.h>

/// Fiber attributes.
struct fiber_attr {
	/**
	 * A flag specifying a fiber to save and restore the signal mask (only
	 * supported on POSIX platforms).
	 */
	unsigned save_mask : 1;
	/**
	 * A flag specifying a fiber to save and restore the floating-point
	 * environment.
	 */
	unsigned save_fenv : 1;
	/**
	 * A flag specifying a fiber to save and restore the error values (i.e.,
	 * errno and GetLastError() on Windows).
	 */
	unsigned save_error : 1;
	/**
	 * A flag specifying a fiber to add a guard page when allocating the
	 * stack frame so that the kernel generates a SIGSEGV signal on stack
	 * overflow (only supported on those POSIX platforms where mmap()
	 * supports anonymous mappings). This flag cannot be used with a
	 * pre-allocated stack, nor with fiber_thrd_init(), since a thread
	 * already has a stack.
	 */
	unsigned guard_stack : 1;
	/**
	 * The size (in bytes) of the data region of a fiber. If not 0, and if
	 * #data_addr is NULL, the data region will be allocated on fiber
	 * creation.
	 */
	size_t data_size;
	/**
	 * A pointer to the first byte of the data region of a fiber. If NULL,
	 * and if #data_size is not 0, a date region will be allocated on fiber
	 * creation.
	 */
	void *data_addr;
	/**
	 * The size (in bytes) of the stack frame of a fiber. If #stack_addr is
	 * NULL, a stack frame will be allocated on fiber creation. The size of
	 * the allocated stack is always at least #LELY_FIBER_MINSTKSZ bytes. If
	 * <b>stack_size</b> is 0, the default size (#LELY_FIBER_STKSZ) is used.
	 */
	size_t stack_size;
#if !_WIN32
	/**
	 * A pointer to the first byte of a memory region to be used as the
	 * stack frame for a fiber. If NULL, a stack frame will be allocated on
	 * fiber creation. If not NULL, it is the responsibility of the caller
	 * to ensure proper alignment.
	 */
	void *stack_addr;
#endif
};

/// The static initializer for #fiber_attr.
#if _WIN32
#define FIBER_ATTR_INIT \
	{ \
		0, 0, 0, 0, 0, NULL, 0 \
	}
#else
#define FIBER_ATTR_INIT \
	{ \
		0, 0, 0, 0, 0, NULL, 0, NULL \
	}
#endif

/// The opaque fiber data type.
typedef struct fiber fiber_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The type of the function executed by a fiber. This function can switch to
 * other fibers by calling fiber_resume() or fiber_resume_with(). The function
 * is not required to ever terminate, but if it does, it MUST return a pointer
 * to the fiber to be resumed, or NULL. In the latter case, the (fiber
 * associated with the) current thread resumes execution.
 *
 * @param fiber a pointer to the suspended fiber, i.e., the fiber that invoked
 *              fiber_resume() or fiber_resume_with() to start this fiber. If
 *              <b>fiber</b> is NULL, this fiber was resumed by the (fiber
 *              associated with the) current thread.
 * @param arg   the argument supplied to fiber_create().
 *
 * @returns a pointer to the fiber to be resumed, or NULL.
 */
typedef fiber_t *fiber_func_t(fiber_t *fiber, void *arg);

/**
 * Initializes the fiber associated with the calling thread. This is necessary
 * to start a fiber, since fiber_resume() and fiber_resume_with() can only be
 * called from within a valid fiber. This function can be invoked more than once
 * by the same thread. Only the first invocation initializes the fiber.
 *
 * @param attr a pointer to the fiber attributes. If <b>attr</b> is NULL, the
 *             default attributes are used. Attributes relating to the data
 *             region and stack are ignored.
 *
 * @returns 1 if a fiber already is associated with the calling thread, 0 if it
 * has been successfully initialized, or -1 on error. In the latter case, the
 * error number can be obtained with get_errc().
 *
 * @see fiber_thrd_fini()
 */
int fiber_thrd_init(const struct fiber_attr *attr);

/**
 * Finalizes the fiber associated with the calling thread. This function MUST be
 * called once for each successful call to fiber_thrd_init(). Only the last
 * invocation finalizes the fiber.
 *
 * @see fiber_thrd_init()
 */
void fiber_thrd_fini(void);

/**
 * Creates a new fiber, allocates a stack and sets up a calling environment to
 * begin executing the specified function. The function is not executed until
 * the fiber is resumed with fiber_resume() or fiber_resume_with().
 *
 * @param attr a pointer to the fiber attributes. If <b>attr</b> is NULL, the
 *             default attributes are used.
 * @param func the function to be executed by the fiber (can be NULL).
 * @param arg  the second argument supplied to <b>func</b>.
 *
 * @returns a pointer to the new fiber, or NULL on error. In the latter case,
 * the error number can be obtained with get_errc().
 */
fiber_t *fiber_create(
		const struct fiber_attr *attr, fiber_func_t *func, void *arg);

/**
 * Destroys the specified fiber. If <b>fiber</b> is NULL or points to the fiber
 * associated with the calling thread, this function has no effect. Destroying
 * the calling fiber or a fiber running in another thread is undefined behavior.
 */
void fiber_destroy(fiber_t *fiber);

/**
 * Copies the attributes of the specified fiber to <b>pattr</b>, or of the
 * calling fiber if <b>fiber</b> is NULL.
 */
void fiber_get_attr(fiber_t *fiber, struct fiber_attr *pattr);

/**
 * Returns a pointer to the data region of the specified fiber, or of the
 * calling fiber if <b>fiber</b> is NULL. The address is obtained from the
 * <b>data_addr</b> member of the fiber attributes.
 *
 * @see fiber_get_attr()
 */
void *fiber_data(const fiber_t *fiber);

/// Equivalent to `fiber_resume_with(fiber, NULL, NULL)`.
fiber_t *fiber_resume(fiber_t *fiber);

/**
 * Suspends the calling fiber and resumes the specified fiber, optionally
 * executing a function before resuming the suspended function.
 *
 * Note that this function MUST be called from a valid fiber created
 * by fiber_create() or fiber_thrd_init().
 *
 * @param fiber a pointer to the fiber to be resumed. If <b>fiber</b> is NULL,
 *              the fiber associated with the calling thread is resumed.
 * @param func  a pointer to the function to be executed in the context of
 *              <b>fiber</b> before the suspended function resumes. If not NULL,
 *              a pointer to the calling fiber is supplied as the first argument
 *              to <b>func</b> and the result of <b>func</b> is returned to the
 *              suspended function.
 * @param arg   the argument to be supplied to <b>func</b>.
 *
 * @returns a pointer to the suspended fiber, or the result of the function
 * executed in the context of this fiber.
 */
fiber_t *fiber_resume_with(fiber_t *fiber, fiber_func_t *func, void *arg);

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_FIBER_H_
