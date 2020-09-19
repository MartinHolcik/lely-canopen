/**@file
 * This file is part of the utilities library; it contains the implementation of
 * the random number generator functions.
 *
 * @see lely/util/rand.h
 *
 * @copyright 2015-2020 Lely Industries N.V.
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
#include <lely/util/rand.h>

#include <assert.h>

static void rand_un_discard(
		struct rand_un *r, unsigned long long z, unsigned int n);

void
rand_u8_seed(rand_u8_t *r, uint_least64_t seed)
{
	assert(r);

	rand_u64_seed(&r->r, seed);
	r->v = 0;
	r->c = 0;
}

uint_least8_t
rand_u8_get(rand_u8_t *r)
{
	if (r->c--)
		return (r->v >>= 8) & UINT8_C(0xff);
	r->v = rand_u64_get(&r->r);
	r->c = 7;
	return r->v;
}

void
rand_u8_discard(rand_u8_t *r, unsigned long long z)
{
	rand_un_discard(r, z, 64 / 8);
}

void
rand_u16_seed(rand_u16_t *r, uint_least64_t seed)
{
	assert(r);

	rand_u64_seed(&r->r, seed);
	r->v = 0;
	r->c = 0;
}

uint_least16_t
rand_u16_get(rand_u16_t *r)
{
	if (r->c--)
		return (r->v >>= 16) & UINT16_C(0xffff);
	r->v = rand_u64_get(&r->r);
	r->c = 3;
	return r->v;
}

void
rand_u16_discard(rand_u16_t *r, unsigned long long z)
{
	rand_un_discard(r, z, 64 / 16);
}

void
rand_u32_seed(rand_u32_t *r, uint_least64_t seed)
{
	assert(r);

	rand_u64_seed(&r->r, seed);
	r->v = 0;
	r->c = 0;
}

uint_least32_t
rand_u32_get(rand_u32_t *r)
{
	if (r->c--)
		return (r->v >>= 32) & UINT32_C(0xffffffff);
	r->v = rand_u64_get(&r->r);
	r->c = 1;
	return r->v;
}

void
rand_u32_discard(rand_u32_t *r, unsigned long long z)
{
	rand_un_discard(r, z, 64 / 32);
}

void
rand_u64_seed(rand_u64_t *r, uint_least64_t seed)
{
	assert(r);

	r->u = seed;
	r->v = UINT64_C(4101842887655102017);
	r->w = 1;

	r->u ^= r->v;
	rand_u64_discard(r, 1);
	r->v = r->u;
	rand_u64_discard(r, 1);
	r->w = r->v;
	rand_u64_discard(r, 1);
}

uint_least64_t
rand_u64_get(rand_u64_t *r)
{
	rand_u64_discard(r, 1);

	uint_least64_t x = r->u ^ (r->u << 21);
	x ^= x >> 35;
	x ^= x << 4;
	return (x + r->v) ^ r->w;
}

void
rand_u64_discard(rand_u64_t *r, unsigned long long z)
{
	assert(r);

	while (z--) {
		r->u *= UINT64_C(2862933555777941757);
		r->u += UINT64_C(7046029254386353087);
		r->v ^= r->v >> 17;
		r->v ^= r->v << 31;
		r->v ^= r->v >> 8;
		r->w = UINT32_C(4294957665) * (r->w & UINT32_C(0xffffffff))
				+ (r->w >> 32);
	}
}

static void
rand_un_discard(struct rand_un *r, unsigned long long z, unsigned int n)
{
	assert(r);

	if (z > r->c) {
		z -= r->c;
		r->c = 0;
		if (z > n) {
			rand_u64_discard(&r->r, (z - 1) / n);
			z = (z - 1) % n + 1;
		}
		r->v = rand_u64_get(&r->r);
		r->c = n;
	}

	if (z) {
		r->v >>= (z - 1) * (64 / n);
		r->c -= z;
	}
}
