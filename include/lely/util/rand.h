/**@file
 * This header file is part of the utilities library; it contains the random
 * number generator declarations.
 *
 * The implementation of the random number generator is based on Numerical
 * Recipes (3rd edition), paragraph 7.1. It generates 64-bit uniformly
 * distributed random numbers with a period of more than 3 * 10^57.
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

#ifndef LELY_UTIL_RAND_H_
#define LELY_UTIL_RAND_H_

#include <lely/features.h>

#include <stdint.h>

/// A 64-bit uniformly distributed unsigned random number generator.
typedef struct {
	/// The first state value of the generator.
	uint_least64_t u;
	/// The second state value of the generator.
	uint_least64_t v;
	/// The third state value of the generator.
	uint_least64_t w;
} rand_u64_t;

/**
 * The state of a uniformly distributed random number generator for numbers
 * smaller than 64 bits. This generator uses all bits of the 64-bit base
 * generator, instead of discarding the higher bits.
 */
typedef struct rand_un {
	/// The 64-bit base generator.
	rand_u64_t r;
	/// The current set of randum numbers.
	uint_least64_t v;
	/// The number of random numbers left in #v.
	unsigned int c;
} rand_u8_t, rand_u16_t, rand_u32_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * (Re)initializes the state of an 8-bit random number generator with a new seed
 * value.
 */
void rand_u8_seed(rand_u8_t *r, uint_least64_t seed);

/**
 * Advances the state of an 8-bit unsigned random number generator and returns
 * the generated value.
 */
uint_least8_t rand_u8_get(rand_u8_t *r);

/**
 * Advances the state of an 8-bit random number generator by <b>z</b> times.
 * Equivalent to calling `rand_u8_get(r)` <b>z</b> times and discarding the
 * result.
 */
void rand_u8_discard(rand_u8_t *r, unsigned long long z);

/**
 * (Re)initializes the state of a 16-bit random number generator with a new seed
 * value.
 */
void rand_u16_seed(rand_u16_t *r, uint_least64_t seed);

/**
 * Advances the state of a 16-bit unsigned random number generator and returns
 * the generated value.
 */
uint_least16_t rand_u16_get(rand_u16_t *r);

/**
 * Advances the state of a 16-bit random number generator by <b>z</b> times.
 * Equivalent to calling `rand_u16_get(r)` <b>z</b> times and discarding the
 * result.
 */
void rand_u16_discard(rand_u16_t *r, unsigned long long z);

/**
 * (Re)initializes the state of a 32-bit random number generator with a new seed
 * value.
 */
void rand_u32_seed(rand_u32_t *r, uint_least64_t seed);

/**
 * Advances the state of a 32-bit unsigned random number generator and returns
 * the generated value.
 */
uint_least32_t rand_u32_get(rand_u32_t *r);

/**
 * Advances the state of a 32-bit random number generator by <b>z</b> times.
 * Equivalent to calling `rand_u32_get(r)` <b>z</b> times and discarding the
 * result.
 */
void rand_u32_discard(rand_u32_t *r, unsigned long long z);

/**
 * (Re)initializes the state of a 64-bit random number generator with a new seed
 * value.
 */
void rand_u64_seed(rand_u64_t *r, uint_least64_t seed);

/**
 * Advances the state of a 64-bit unsigned random number generator and returns
 * the generated value.
 */
uint_least64_t rand_u64_get(rand_u64_t *r);

/**
 * Advances the state of a 64-bit random number generator by <b>z</b> times.
 * Equivalent to calling `rand_u64_get(r)` <b>z</b> times and discarding the
 * result.
 */
void rand_u64_discard(rand_u64_t *r, unsigned long long z);

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_RAND_H_
