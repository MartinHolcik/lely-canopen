/**@file
 * This header file is part of the utilities library; it contains the coroutine
 * scheduler declarations.
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

#ifndef LELY_UTIL_CORO_SCHED_H_
#define LELY_UTIL_CORO_SCHED_H_

#include <lely/util/coro.h>
#include <lely/util/dllist.h>

#ifndef LELY_UTIL_CORO_SCHED_INLINE
#define LELY_UTIL_CORO_SCHED_INLINE static inline
#endif

struct coro {
	struct dlnode node;
};

#ifdef __cplusplus
extern "C" {
#endif

struct coro_sched_ctor_vtbl {
	coro_sched_t *(*create)(coro_sched_ctor_t *ctor);
	void (*destroy)(coro_sched_ctor_t *ctor, coro_sched_t *sched);
};

LELY_UTIL_CORO_SCHED_INLINE coro_sched_t *coro_sched_create(
		coro_sched_ctor_t *ctor);
LELY_UTIL_CORO_SCHED_INLINE void coro_sched_destroy(
		coro_sched_ctor_t *ctor, coro_sched_t *sched);

struct coro_sched_vtbl {
	void (*push)(coro_sched_t *sched, coro_t coro);
	coro_t (*pop)(coro_sched_t *sched);
	void (*wait)(coro_sched_t *sched, const struct timespec *tp);
	void (*signal)(coro_sched_t *sched);
};

LELY_UTIL_CORO_SCHED_INLINE void coro_sched_push(
		coro_sched_t *sched, coro_t coro);
LELY_UTIL_CORO_SCHED_INLINE coro_t coro_sched_pop(coro_sched_t *sched);
LELY_UTIL_CORO_SCHED_INLINE void coro_sched_wait(
		coro_sched_t *, const struct timespec *ts);
LELY_UTIL_CORO_SCHED_INLINE void coro_sched_signal(coro_sched_t *sched);

coro_sched_ctor_t *coro_sched_rr_ctor(void);

coro_sched_ctor_t *coro_sched_sw_ctor(void);

coro_sched_ctor_t *coro_sched_ws_ctor(size_t nsteal);

inline coro_sched_t *
coro_sched_create(coro_sched_ctor_t *ctor)
{
	return (*ctor)->create(ctor);
}

inline void
coro_sched_destroy(coro_sched_ctor_t *ctor, coro_sched_t *sched)
{
	(*ctor)->destroy(ctor, sched);
}

inline void
coro_sched_push(coro_sched_t *sched, coro_t coro)
{
	(*sched)->push(sched, coro);
}

inline coro_t
coro_sched_pop(coro_sched_t *sched)
{
	return (*sched)->pop(sched);
}

inline void
coro_sched_wait(coro_sched_t *sched, const struct timespec *tp)
{
	(*sched)->wait(sched, tp);
}

inline void
coro_sched_signal(coro_sched_t *sched)
{
	(*sched)->signal(sched);
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_CORO_SCHED_H_
