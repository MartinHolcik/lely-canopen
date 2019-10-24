/**@file
 * This file is part of the CANopen library; it contains the implementation of
 * the CANopen value functions.
 *
 * @see lely/co/val.h
 *
 * @copyright 2017-2019 Lely Industries N.V.
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

#include "co.h"
#include <lely/co/sdo.h>
#include <lely/co/val.h>
#include <lely/libc/string.h>
#include <lely/util/cmp.h>
#include <lely/util/diag.h>
#include <lely/util/endian.h>
#include <lely/util/lex.h>
#include <lely/util/print.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#define CO_BOOLEAN_INIT 0
#define CO_INTEGER8_INIT 0
#define CO_INTEGER16_INIT 0
#define CO_INTEGER32_INIT 0
#define CO_UNSIGNED8_INIT 0
#define CO_UNSIGNED16_INIT 0
#define CO_UNSIGNED32_INIT 0
#define CO_REAL32_INIT 0
#define CO_VISIBLE_STRING_INIT NULL
#define CO_OCTET_STRING_INIT NULL
#define CO_UNICODE_STRING_INIT NULL
#define CO_TIME_OF_DAY_INIT \
	{ \
		0, 0 \
	}
#define CO_TIME_DIFF_INIT CO_TIME_OF_DAY_INIT
#define CO_DOMAIN_INIT NULL
#define CO_INTEGER24_INIT 0
#define CO_REAL64_INIT 0
#define CO_INTEGER40_INIT 0
#define CO_INTEGER48_INIT 0
#define CO_INTEGER56_INIT 0
#define CO_INTEGER64_INIT 0
#define CO_UNSIGNED24_INIT 0
#define CO_UNSIGNED40_INIT 0
#define CO_UNSIGNED48_INIT 0
#define CO_UNSIGNED56_INIT 0
#define CO_UNSIGNED64_INIT 0

#define CO_VISIBLE_STRING_MIN NULL
#define CO_VISIBLE_STRING_MAX NULL

#define CO_OCTET_STRING_MIN NULL
#define CO_OCTET_STRING_MAX NULL

#define CO_UNICODE_STRING_MIN NULL
#define CO_UNICODE_STRING_MAX NULL

#define CO_DOMAIN_MIN NULL
#define CO_DOMAIN_MAX NULL

#define CO_ARRAY_OFFSET ALIGN(sizeof(size_t), _Alignof(union co_val))

static int co_array_alloc(void *val, size_t size);
static void co_array_free(void *val);
static void co_array_init(void *val, size_t size);
static void co_array_fini(void *val);

static size_t co_array_sizeof(const void *val);

/**
 * Returns the number of (16-bit) Unicode characters, excluding the terminating
 * null bytes, in the string at <b>s</b>.
 */
static size_t str16len(const char16_t *s);

/**
 * Copies at most <b>n</b> (16-bit) Unicode characters from the string at
 * <b>src</b> to <b>dst</b>.
 *
 * @param dst the destination address, which MUST be large enough to hold the
 *            string.
 * @param src a pointer to the string to be copied.
 * @param n   the maximum number of (16-bit) Unicode characters to copy.
 *
 * @returns <b>dst</b>.
 */
static char16_t *str16ncpy(char16_t *dst, const char16_t *src, size_t n);

/**
 * Compares two (16-bit) Unicode strings.
 *
 * @param s1 a pointer to the first string.
 * @param s2 a pointer to the second string.
 * @param n  the maximum number of characters to compare.
 *
 * @returns an integer greater than, equal to, or less than 0 if the string at
 * <b>s1</b> is greater than, equal to, or less than the string at <b>s2</b>.
 */
static int str16ncmp(const char16_t *s1, const char16_t *s2, size_t n);

int
co_val_init(co_unsigned16_t type, void *val)
{
	union co_val *u = val;
	assert(u);

	switch (type) {
#define LELY_CO_DEFINE_TYPE(a, b, c, d) \
	case CO_DEFTYPE_##a: \
		u->c = (co_##b##_t)CO_##a##_INIT; \
		return 0;
#include <lely/co/def/type.def>
#undef LELY_CO_DEFINE_TYPE
	default: set_errnum(ERRNUM_INVAL); return -1;
	}
}

int
co_val_init_min(co_unsigned16_t type, void *val)
{
	union co_val *u = val;
	assert(u);

	switch (type) {
#define LELY_CO_DEFINE_TYPE(a, b, c, d) \
	case CO_DEFTYPE_##a: \
		u->c = (co_##b##_t)CO_##a##_MIN; \
		return 0;
#include <lely/co/def/type.def>
#undef LELY_CO_DEFINE_TYPE
	default: set_errnum(ERRNUM_INVAL); return -1;
	}
}

int
co_val_init_max(co_unsigned16_t type, void *val)
{
	union co_val *u = val;
	assert(u);

	switch (type) {
#define LELY_CO_DEFINE_TYPE(a, b, c, d) \
	case CO_DEFTYPE_##a: \
		u->c = (co_##b##_t)CO_##a##_MAX; \
		return 0;
#include <lely/co/def/type.def>
#undef LELY_CO_DEFINE_TYPE
	default: set_errnum(ERRNUM_INVAL); return -1;
	}
}

int
co_val_init_vs(char **val, const char *vs)
{
	assert(val);

	if (vs)
		return co_val_init_vs_n(val, vs, strlen(vs));

	*val = NULL;

	return 0;
}

int
co_val_init_vs_n(char **val, const char *vs, size_t n)
{
	assert(val);

	if (n) {
		if (co_array_alloc(val, n + 1) == -1)
			return -1;
		assert(*val);
		co_array_init(val, n);
		if (vs)
			strncpy(*val, vs, n);
	} else {
		*val = NULL;
	}

	return 0;
}

int
co_val_init_os(uint8_t **val, const uint8_t *os, size_t n)
{
	assert(val);

	if (n) {
		if (co_array_alloc(val, n + 1) == -1)
			return -1;
		assert(*val);
		co_array_init(val, n);
		if (os)
			memcpy(*val, os, n);
	} else {
		*val = NULL;
	}

	return 0;
}

int
co_val_init_us(char16_t **val, const char16_t *us)
{
	assert(val);

	if (us)
		return co_val_init_us_n(val, us, str16len(us));

	*val = NULL;

	return 0;
}

int
co_val_init_us_n(char16_t **val, const char16_t *us, size_t n)
{
	assert(val);

	if (n) {
		if (co_array_alloc(val, 2 * (n + 1)) == -1)
			return -1;
		assert(*val);
		co_array_init(val, 2 * n);
		if (us)
			str16ncpy(*val, us, n);
	} else {
		*val = NULL;
	}

	return 0;
}

int
co_val_init_dom(void **val, const void *dom, size_t n)
{
	assert(val);

	if (n) {
		if (co_array_alloc(val, n) == -1)
			return -1;
		assert(*val);
		co_array_init(val, n);
		if (dom)
			memcpy(*val, dom, n);
	} else {
		*val = NULL;
	}

	return 0;
}

void
co_val_fini(co_unsigned16_t type, void *val)
{
	assert(val);

	if (co_type_is_array(type)) {
		co_array_free(val);
		co_array_fini(val);
	}
}

const void *
co_val_addressof(co_unsigned16_t type, const void *val)
{
	if (!val)
		return NULL;

	return co_type_is_array(type) ? *(const void **)val : val;
}

size_t
co_val_sizeof(co_unsigned16_t type, const void *val)
{
	if (!val)
		return 0;

	// clang-format off
	return co_type_is_array(type)
			? co_array_sizeof(val)
			: co_type_sizeof(type);
	// clang-format on
}

size_t
co_val_make(co_unsigned16_t type, void *val, const void *ptr, size_t n)
{
	assert(val);

	switch (type) {
	case CO_DEFTYPE_VISIBLE_STRING:
		n = ptr ? strlen(ptr) : 0;
		if (co_val_init_vs(val, ptr) == -1)
			return 0;
		break;
	case CO_DEFTYPE_OCTET_STRING:
		if (!ptr)
			n = 0;
		if (co_val_init_os(val, ptr, n) == -1)
			return 0;
		break;
	case CO_DEFTYPE_UNICODE_STRING:
		n = ptr ? str16len(ptr) : 0;
		if (co_val_init_us(val, ptr) == -1)
			return 0;
		break;
	case CO_DEFTYPE_DOMAIN:
		if (!ptr)
			n = 0;
		if (co_val_init_dom(val, ptr, n) == -1)
			return 0;
		break;
	default:
		if (!ptr || co_type_sizeof(type) != n)
			return 0;
		memcpy(val, ptr, n);
	}
	return n;
}

size_t
co_val_copy(co_unsigned16_t type, void *dst, const void *src)
{
	assert(dst);
	assert(src);

	size_t n;
	if (co_type_is_array(type)) {
		const void *ptr = co_val_addressof(type, src);
		n = co_val_sizeof(type, src);
		switch (type) {
		case CO_DEFTYPE_VISIBLE_STRING:
			if (co_val_init_vs(dst, ptr) == -1)
				return 0;
			break;
		case CO_DEFTYPE_OCTET_STRING:
			if (co_val_init_os(dst, ptr, n) == -1)
				return 0;
			break;
		case CO_DEFTYPE_UNICODE_STRING:
			if (co_val_init_us(dst, ptr) == -1)
				return 0;
			break;
		case CO_DEFTYPE_DOMAIN:
			if (co_val_init_dom(dst, ptr, n) == -1)
				return 0;
			break;
		default:
			// We can never get here.
			return 0;
		}
	} else {
		n = co_type_sizeof(type);
		memcpy(dst, src, n);
	}
	return n;
}

size_t
co_val_move(co_unsigned16_t type, void *dst, void *src)
{
	assert(dst);
	assert(src);

	size_t n = co_type_sizeof(type);
	memcpy(dst, src, n);

	if (co_type_is_array(type))
		co_array_fini(src);

	return n;
}

int
co_val_cmp(co_unsigned16_t type, const void *v1, const void *v2)
{
	if (v1 == v2)
		return 0;

	if (!v1)
		return -1;
	if (!v2)
		return 1;

	int cmp = 0;
	if (co_type_is_array(type)) {
		const void *p1 = co_val_addressof(type, v1);
		const void *p2 = co_val_addressof(type, v2);

		if (p1 == p2)
			return 0;

		if (!p1)
			return -1;
		if (!p2)
			return 1;

		size_t n1 = co_val_sizeof(type, v1);
		size_t n2 = co_val_sizeof(type, v2);
		switch (type) {
		case CO_DEFTYPE_VISIBLE_STRING:
			cmp = strncmp(p1, p2, MIN(n1, n2));
			break;
		case CO_DEFTYPE_OCTET_STRING:
			cmp = memcmp(p1, p2, MIN(n1, n2));
			break;
		case CO_DEFTYPE_UNICODE_STRING:
			cmp = str16ncmp(p1, p2, MIN(n1, n2) / 2);
			break;
		case CO_DEFTYPE_DOMAIN:
			cmp = memcmp(p1, p2, MIN(n1, n2));
			break;
		default:
			// We can never get here.
			return 0;
		}
		if (!cmp)
			cmp = (n1 > n2) - (n1 < n2);
		return cmp;
	} else {
		const union co_val *u1 = v1;
		const union co_val *u2 = v2;
		switch (type) {
		case CO_DEFTYPE_BOOLEAN: return bool_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER8: return int8_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER16: return int16_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER32: return int32_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED8: return uint8_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED16: return uint16_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED32: return uint32_cmp(v1, v2);
		case CO_DEFTYPE_REAL32: return flt_cmp(v1, v2);
		case CO_DEFTYPE_TIME_OF_DAY:
			cmp = uint32_cmp(&u1->t.ms, &u2->t.ms);
			if (!cmp)
				cmp = uint16_cmp(&u1->t.days, &u2->t.days);
			return cmp;
		case CO_DEFTYPE_TIME_DIFF:
			cmp = uint32_cmp(&u1->td.ms, &u2->td.ms);
			if (!cmp)
				cmp = uint16_cmp(&u1->td.days, &u2->td.days);
			return cmp;
		case CO_DEFTYPE_INTEGER24: return int32_cmp(v1, v2);
		case CO_DEFTYPE_REAL64: return dbl_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER40: return int64_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER48: return int64_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER56: return int64_cmp(v1, v2);
		case CO_DEFTYPE_INTEGER64: return int64_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED24: return uint32_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED40: return uint64_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED48: return uint64_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED56: return uint64_cmp(v1, v2);
		case CO_DEFTYPE_UNSIGNED64: return uint64_cmp(v1, v2);
		default: return 0;
		}
	}
}

size_t
co_val_read(co_unsigned16_t type, void *val, const uint8_t *begin,
		const uint8_t *end)
{
	assert(begin || begin == end);
	assert(!end || end >= begin);

	size_t n = end - begin;

	if (co_type_is_array(type)) {
		if (val) {
			switch (type) {
			case CO_DEFTYPE_VISIBLE_STRING:
				// clang-format off
				if (co_val_init_vs_n(val, (const char *)begin,
						n) == -1)
					// clang-format on
					return 0;
				break;
			case CO_DEFTYPE_OCTET_STRING:
				if (co_val_init_os(val, begin, n) == -1)
					return 0;
				break;
			case CO_DEFTYPE_UNICODE_STRING:
				if (co_val_init_us_n(val, NULL, n / 2) == -1)
					return 0;
				if (n) {
					char16_t *us = *(char16_t **)val;
					assert(us);
					for (size_t i = 0; i + 1 < n; i += 2)
						us[i / 2] = ldle_u16(begin + i);
				}
				break;
			case CO_DEFTYPE_DOMAIN:
				if (co_val_init_dom(val, begin, n) == -1)
					return 0;
				break;
			default:
				// We can never get here.
				return 0;
			}
		}
		return n;
	} else {
		union co_val *u = val;
		switch (type) {
		case CO_DEFTYPE_BOOLEAN:
			if (n < 1)
				return 0;
			if (u)
				u->b = !!*(const co_boolean_t *)begin;
			return 1;
		case CO_DEFTYPE_INTEGER8:
			if (n < 1)
				return 0;
			if (u)
				u->i8 = *(const co_integer8_t *)begin;
			return 1;
		case CO_DEFTYPE_INTEGER16:
			if (n < 2)
				return 0;
			if (u)
				u->i16 = ldle_i16(begin);
			return 2;
		case CO_DEFTYPE_INTEGER32:
			if (n < 4)
				return 0;
			if (u)
				u->i32 = ldle_i32(begin);
			return 4;
		case CO_DEFTYPE_UNSIGNED8:
			if (n < 1)
				return 0;
			if (u)
				u->u8 = *(const co_unsigned8_t *)begin;
			return 1;
		case CO_DEFTYPE_UNSIGNED16:
			if (n < 2)
				return 0;
			if (u)
				u->u16 = ldle_u16(begin);
			return 2;
		case CO_DEFTYPE_UNSIGNED32:
			if (n < 4)
				return 0;
			if (u)
				u->u32 = ldle_u32(begin);
			return 4;
		case CO_DEFTYPE_REAL32:
			if (n < 4)
				return 0;
			if (u)
				u->r32 = ldle_flt32(begin);
			return 4;
		case CO_DEFTYPE_TIME_OF_DAY:
		case CO_DEFTYPE_TIME_DIFF:
			if (n < 6)
				return 0;
			if (u) {
				u->t.ms = ldle_u32(begin)
						& UINT32_C(0x0fffffff);
				u->t.days = ldle_u16(begin + 4);
			}
			return 6;
		case CO_DEFTYPE_INTEGER24:
			if (n < 3)
				return 0;
			if (u) {
				co_unsigned24_t u24 = 0;
				for (size_t i = 0; i < 3; i++)
					u24 |= (co_unsigned24_t)*begin++
							<< 8 * i;
				u->i24 = u24 > CO_INTEGER24_MAX
						? -(CO_UNSIGNED24_MAX + 1 - u24)
						: u24;
			}
			return 3;
		case CO_DEFTYPE_REAL64:
			if (n < 8)
				return 0;
			if (u)
				u->r64 = ldle_flt64(begin);
			return 8;
		case CO_DEFTYPE_INTEGER40:
			if (n < 5)
				return 0;
			if (u) {
				co_unsigned40_t u40 = 0;
				for (size_t i = 0; i < 5; i++)
					u40 |= (co_unsigned40_t)*begin++
							<< 8 * i;
				u->i40 = u40 > CO_INTEGER40_MAX
						? -(CO_UNSIGNED40_MAX + 1 - u40)
						: u40;
			}
			return 5;
		case CO_DEFTYPE_INTEGER48:
			if (n < 6)
				return 0;
			if (u) {
				co_unsigned48_t u48 = 0;
				for (size_t i = 0; i < 6; i++)
					u48 |= (co_unsigned48_t)*begin++
							<< 8 * i;
				u->i48 = u48 > CO_INTEGER48_MAX
						? -(CO_UNSIGNED48_MAX + 1 - u48)
						: u48;
			}
			return 6;
		case CO_DEFTYPE_INTEGER56:
			if (n < 7)
				return 0;
			if (u) {
				co_unsigned56_t u56 = 0;
				for (size_t i = 0; i < 7; i++)
					u56 |= (co_unsigned56_t)*begin++
							<< 8 * i;
				u->i56 = u56 > CO_INTEGER56_MAX
						? -(CO_UNSIGNED56_MAX + 1 - u56)
						: u56;
			}
			return 7;
		case CO_DEFTYPE_INTEGER64:
			if (n < 8)
				return 0;
			if (u)
				u->i64 = ldle_i64(begin);
			return 8;
		case CO_DEFTYPE_UNSIGNED24:
			if (n < 3)
				return 0;
			if (u) {
				u->u24 = 0;
				for (size_t i = 0; i < 3; i++)
					u->u24 |= (co_unsigned24_t)*begin++
							<< 8 * i;
			}
			return 3;
		case CO_DEFTYPE_UNSIGNED40:
			if (n < 5)
				return 0;
			if (u) {
				u->u40 = 0;
				for (size_t i = 0; i < 5; i++)
					u->u40 |= (co_unsigned40_t)*begin++
							<< 8 * i;
			}
			return 5;
		case CO_DEFTYPE_UNSIGNED48:
			if (n < 6)
				return 0;
			if (u) {
				u->u48 = 0;
				for (size_t i = 0; i < 6; i++)
					u->u48 |= (co_unsigned48_t)*begin++
							<< 8 * i;
			}
			return 6;
		case CO_DEFTYPE_UNSIGNED56:
			if (n < 7)
				return 0;
			if (u) {
				u->u56 = 0;
				for (size_t i = 0; i < 7; i++)
					u->u56 |= (co_unsigned56_t)*begin++
							<< 8 * i;
			}
			return 7;
		case CO_DEFTYPE_UNSIGNED64:
			if (n < 8)
				return 0;
			if (u)
				u->u64 = ldle_u64(begin);
			return 8;
		default: set_errnum(ERRNUM_INVAL); return 0;
		}
	}
}

co_unsigned32_t
co_val_read_sdo(co_unsigned16_t type, void *val, const void *ptr, size_t n)
{
	int errc = get_errc();
	co_unsigned32_t ac = 0;

	const uint8_t *begin = ptr;
	const uint8_t *end = begin ? begin + n : NULL;
	if (n && !co_val_read(type, val, begin, end)) {
		// clang-format off
		ac = get_errnum() == ERRNUM_NOMEM
				? CO_SDO_AC_NO_MEM
				: CO_SDO_AC_ERROR;
		// clang-format on
		set_errc(errc);
	}

	return ac;
}

size_t
co_val_write(co_unsigned16_t type, const void *val, uint8_t *begin,
		uint8_t *end)
{
	assert(val);

	if (co_type_is_array(type)) {
		const void *ptr = co_val_addressof(type, val);
		size_t n = co_val_sizeof(type, val);
		if (!ptr || !n)
			return 0;
		if (begin && (!end || end - begin >= (ptrdiff_t)n)) {
			switch (type) {
			case CO_DEFTYPE_VISIBLE_STRING:
				memcpy(begin, ptr, n);
				break;
			case CO_DEFTYPE_OCTET_STRING:
				memcpy(begin, ptr, n);
				break;
			case CO_DEFTYPE_UNICODE_STRING: {
				const char16_t *us = ptr;
				for (size_t i = 0; i + 1 < n; i += 2)
					stle_u16(begin + i, us[i / 2]);
				break;
			}
			case CO_DEFTYPE_DOMAIN: memcpy(begin, ptr, n); break;
			default:
				// We can never get here.
				return 0;
			}
		}
		return n;
	} else {
		const union co_val *u = val;
		switch (type) {
		case CO_DEFTYPE_BOOLEAN:
			if (begin && (!end || end - begin >= 1))
				*(co_boolean_t *)begin = !!u->b;
			return 1;
		case CO_DEFTYPE_INTEGER8:
			if (begin && (!end || end - begin >= 1))
				*(co_integer8_t *)begin = u->i8;
			return 1;
		case CO_DEFTYPE_INTEGER16:
			if (begin && (!end || end - begin >= 2))
				stle_i16(begin, u->i16);
			return 2;
		case CO_DEFTYPE_INTEGER32:
			if (begin && (!end || end - begin >= 4))
				stle_i32(begin, u->i32);
			return 4;
		case CO_DEFTYPE_UNSIGNED8:
			if (begin && (!end || end - begin >= 1))
				*(co_unsigned8_t *)begin = u->u8;
			return 1;
		case CO_DEFTYPE_UNSIGNED16:
			if (begin && (!end || end - begin >= 2))
				stle_u16(begin, u->u16);
			return 2;
		case CO_DEFTYPE_UNSIGNED32:
			if (begin && (!end || end - begin >= 4))
				stle_u32(begin, u->u32);
			return 4;
		case CO_DEFTYPE_REAL32:
			if (begin && (!end || end - begin >= 4))
				stle_flt32(begin, u->r32);
			return 4;
		case CO_DEFTYPE_TIME_OF_DAY:
		case CO_DEFTYPE_TIME_DIFF:
			if (begin && (!end || end - begin >= 6)) {
				stle_u32(begin, u->t.ms & UINT32_C(0x0fffffff));
				stle_u16(begin + 4, u->t.days);
			}
			return 6;
		case CO_DEFTYPE_INTEGER24:
			if (begin && (!end || end - begin >= 3)) {
				co_unsigned24_t u24 = u->i24 < 0
						? CO_UNSIGNED24_MAX + 1 + u->i24
						: (co_unsigned24_t)u->i24;
				for (size_t i = 0; i < 3; i++)
					*begin++ = (u24 >> 8 * i) & 0xff;
			}
			return 3;
		case CO_DEFTYPE_REAL64:
			if (begin && (!end || end - begin >= 8))
				stle_flt64(begin, u->r64);
			return 8;
		case CO_DEFTYPE_INTEGER40:
			if (begin && (!end || end - begin >= 5)) {
				co_unsigned40_t u40 = u->i40 < 0
						? CO_UNSIGNED40_MAX + 1 + u->i40
						: (co_unsigned40_t)u->i40;
				for (size_t i = 0; i < 5; i++)
					*begin++ = (u40 >> 8 * i) & 0xff;
			}
			return 5;
		case CO_DEFTYPE_INTEGER48:
			if (begin && (!end || end - begin >= 6)) {
				co_unsigned48_t u48 = u->i48 < 0
						? CO_UNSIGNED48_MAX + 1 + u->i48
						: (co_unsigned48_t)u->i48;
				for (size_t i = 0; i < 6; i++)
					*begin++ = (u48 >> 8 * i) & 0xff;
			}
			return 6;
		case CO_DEFTYPE_INTEGER56:
			if (begin && (!end || end - begin >= 7)) {
				co_unsigned56_t u56 = u->i56 < 0
						? CO_UNSIGNED56_MAX + 1 + u->i56
						: (co_unsigned56_t)u->i56;
				for (size_t i = 0; i < 7; i++)
					*begin++ = (u56 >> 8 * i) & 0xff;
			}
			return 7;
		case CO_DEFTYPE_INTEGER64:
			if (begin && (!end || end - begin >= 8))
				stle_i64(begin, u->i64);
			return 8;
		case CO_DEFTYPE_UNSIGNED24:
			if (begin && (!end || end - begin >= 3)) {
				for (size_t i = 0; i < 3; i++)
					*begin++ = (u->u24 >> 8 * i) & 0xff;
			}
			return 3;
		case CO_DEFTYPE_UNSIGNED40:
			if (begin && (!end || end - begin >= 5)) {
				for (size_t i = 0; i < 5; i++)
					*begin++ = (u->u40 >> 8 * i) & 0xff;
			}
			return 5;
		case CO_DEFTYPE_UNSIGNED48:
			if (begin && (!end || end - begin >= 6)) {
				for (size_t i = 0; i < 6; i++)
					*begin++ = (u->u48 >> 8 * i) & 0xff;
			}
			return 6;
		case CO_DEFTYPE_UNSIGNED56:
			if (begin && (!end || end - begin >= 7)) {
				for (size_t i = 0; i < 7; i++)
					*begin++ = (u->u56 >> 8 * i) & 0xff;
			}
			return 7;
		case CO_DEFTYPE_UNSIGNED64:
			if (begin && (!end || end - begin >= 8))
				stle_u64(begin, u->u64);
			return 8;
		default: set_errnum(ERRNUM_INVAL); return 0;
		}
	}
}

size_t
co_val_lex(co_unsigned16_t type, void *val, const char *begin, const char *end,
		struct floc *at)
{
	assert(begin);
	assert(!end || end >= begin);

	// Prevent a previous range error from triggering a spurious warning.
	if (get_errnum() == ERRNUM_RANGE)
		set_errnum(0);

	const char *cp = begin;
	size_t chars = 0;

	union co_val u;
	switch (type) {
	case CO_DEFTYPE_BOOLEAN:
		chars = lex_c99_u8(cp, end, NULL, &u.u8);
		if (chars) {
			cp += chars;
			if (u.u8 > CO_BOOLEAN_MAX) {
				u.u8 = CO_BOOLEAN_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"boolean truth value overflow");
			}
			if (val)
				*(co_boolean_t *)val = u.u8;
		}
		break;
	case CO_DEFTYPE_INTEGER8:
		chars = lex_c99_i8(cp, end, NULL, &u.i8);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.i8 == INT8_MIN)
				diag_if(DIAG_WARNING, get_errc(), at,
						"8-bit signed integer underflow");
			else if (get_errnum() == ERRNUM_RANGE
					&& u.i8 == INT8_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"8-bit signed integer overflow");
			if (val)
				*(co_integer8_t *)val = u.i8;
		}
		break;
	case CO_DEFTYPE_INTEGER16:
		chars = lex_c99_i16(cp, end, NULL, &u.i16);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.i16 == INT16_MIN)
				diag_if(DIAG_WARNING, get_errc(), at,
						"16-bit signed integer underflow");
			else if (get_errnum() == ERRNUM_RANGE
					&& u.i16 == INT16_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"16-bit signed integer overflow");
			if (val)
				*(co_integer16_t *)val = u.i16;
		}
		break;
	case CO_DEFTYPE_INTEGER32:
		chars = lex_c99_i32(cp, end, NULL, &u.i32);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.i32 == INT32_MIN)
				diag_if(DIAG_WARNING, get_errc(), at,
						"32-bit signed integer underflow");
			else if (get_errnum() == ERRNUM_RANGE
					&& u.i32 == INT32_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"32-bit signed integer overflow");
			if (val)
				*(co_integer32_t *)val = u.i32;
		}
		break;
	case CO_DEFTYPE_UNSIGNED8:
		chars = lex_c99_u8(cp, end, NULL, &u.u8);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u8 == UINT8_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"8-bit unsigned integer overflow");
			if (val)
				*(co_unsigned8_t *)val = u.u8;
		}
		break;
	case CO_DEFTYPE_UNSIGNED16:
		chars = lex_c99_u16(cp, end, NULL, &u.u16);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u16 == UINT16_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"16-bit unsigned integer overflow");
			if (val)
				*(co_unsigned16_t *)val = u.u16;
		}
		break;
	case CO_DEFTYPE_UNSIGNED32:
		chars = lex_c99_u32(cp, end, NULL, &u.u32);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u32 == UINT32_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"32-bit unsigned integer overflow");
			if (val)
				*(co_unsigned32_t *)val = u.u32;
		}
		break;
	case CO_DEFTYPE_REAL32:
		chars = lex_c99_u32(cp, end, NULL, &u.u32);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u32 == UINT32_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"32-bit unsigned integer overflow");
			// clang-format off
			u.r32 = ((union {
				uint32_t u32;
				co_real32_t r32;
			}){ u.u32 }).r32;
			// clang-format on
			if (val)
				*(co_real32_t *)val = u.r32;
		}
		break;
	case CO_DEFTYPE_VISIBLE_STRING: {
		size_t n = 0;
		chars = lex_c99_str(cp, end, NULL, NULL, &n);
		if (val) {
			if (co_val_init_vs_n(val, 0, n) == -1) {
				diag_if(DIAG_ERROR, get_errc(), at,
						"unable to create value of type VISIBLE_STRING");
				return 0;
			}
			// Parse the characters.
			char *vs = *(void **)val;
			assert(vs);
			lex_c99_str(cp, end, NULL, vs, &n);
		}
		cp += chars;
		break;
	}
	case CO_DEFTYPE_OCTET_STRING: {
		// Count the number of hexadecimal digits.
		while ((!end || cp + chars < end)
				&& isxdigit((unsigned char)cp[chars]))
			chars++;
		if (val) {
			if (co_val_init_os(val, NULL, (chars + 1) / 2) == -1) {
				diag_if(DIAG_ERROR, get_errc(), at,
						"unable to create value of type OCTET_STRING");
				return 0;
			}
			// Parse the octets.
			uint8_t *os = *(void **)val;
			assert(os);
			for (size_t i = 0; i < chars; i++) {
				if (i % 2) {
					*os <<= 4;
					*os++ |= ctox(cp[i]) & 0xf;
				} else {
					*os = ctox(cp[i]) & 0xf;
				}
			}
		}
		cp += chars;
		break;
	}
	case CO_DEFTYPE_UNICODE_STRING: {
		size_t n = 0;
		chars = lex_base64(cp, end, NULL, NULL, &n);
		if (val) {
			if (co_val_init_us_n(val, NULL, n / 2) == -1) {
				diag_if(DIAG_ERROR, get_errc(), at,
						"unable to create value of type UNICODE_STRING");
				return 0;
			}
			// Parse the Unicode characters.
			char16_t *us = *(void **)val;
			assert(us);
			lex_base64(cp, end, NULL, us, &n);
			for (size_t i = 0; i + 1 < n; i += 2)
				us[i / 2] = letoh16(us[i / 2]);
		}
		cp += chars;
		break;
	}
	case CO_DEFTYPE_TIME_OF_DAY:
	case CO_DEFTYPE_TIME_DIFF:
		chars = lex_c99_u16(cp, end, NULL, &u.t.days);
		if (!chars)
			return 0;
		cp += chars;
		cp += lex_ctype(&isblank, cp, end, NULL);
		chars = lex_c99_u32(cp, end, NULL, &u.t.ms);
		if (!chars)
			return 0;
		cp += chars;
		if (val)
			*(co_time_of_day_t *)val = u.t;
		break;
	case CO_DEFTYPE_DOMAIN: {
		size_t n = 0;
		chars = lex_base64(cp, end, NULL, NULL, &n);
		if (val) {
			if (co_val_init_dom(val, NULL, n) == -1) {
				diag_if(DIAG_ERROR, get_errc(), at,
						"unable to create value of type DOMAIN");
				return 0;
			}
			void *dom = *(void **)val;
			assert(!n || dom);
			lex_base64(cp, end, NULL, dom, &n);
		}
		cp += chars;
		break;
	}
	case CO_DEFTYPE_INTEGER24:
		chars = lex_c99_i32(cp, end, NULL, &u.i32);
		if (chars) {
			cp += chars;
			if (u.i32 < CO_INTEGER24_MIN) {
				u.i32 = CO_INTEGER24_MIN;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"24-bit signed integer underflow");
			} else if (u.i32 > CO_INTEGER24_MAX) {
				u.i32 = CO_INTEGER24_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"24-bit signed integer overflow");
			}
			if (val)
				*(co_integer24_t *)val = u.i32;
		}
		break;
	case CO_DEFTYPE_REAL64:
		chars = lex_c99_u64(cp, end, NULL, &u.u64);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u64 == UINT64_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"64-bit unsigned integer overflow");
			// clang-format off
			u.r64 = ((union {
				uint64_t u64;
				co_real64_t r64;
			}){ u.u64 }).r64;
			// clang-format on
			if (val)
				*(co_real64_t *)val = u.r64;
		}
		break;
	case CO_DEFTYPE_INTEGER40:
		chars = lex_c99_i64(cp, end, NULL, &u.i64);
		if (chars) {
			cp += chars;
			if (u.i64 < CO_INTEGER40_MIN) {
				u.i64 = CO_INTEGER40_MIN;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"40-bit signed integer underflow");
			} else if (u.i64 > CO_INTEGER40_MAX) {
				u.i64 = CO_INTEGER40_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"40-bit signed integer overflow");
			}
			if (val)
				*(co_integer40_t *)val = u.i64;
		}
		break;
	case CO_DEFTYPE_INTEGER48:
		chars = lex_c99_i64(cp, end, NULL, &u.i64);
		if (chars) {
			cp += chars;
			if (u.i64 < CO_INTEGER48_MIN) {
				u.i64 = CO_INTEGER48_MIN;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"48-bit signed integer underflow");
			} else if (u.i64 > CO_INTEGER48_MAX) {
				u.i64 = CO_INTEGER48_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"48-bit signed integer overflow");
			}
			if (val)
				*(co_integer48_t *)val = u.i64;
		}
		break;
	case CO_DEFTYPE_INTEGER56:
		chars = lex_c99_i64(cp, end, NULL, &u.i64);
		if (chars) {
			cp += chars;
			if (u.i64 < CO_INTEGER56_MIN) {
				u.i64 = CO_INTEGER56_MIN;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"56-bit signed integer underflow");
			} else if (u.i64 > CO_INTEGER56_MAX) {
				u.i64 = CO_INTEGER56_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"56-bit signed integer overflow");
			}
			if (val)
				*(co_integer56_t *)val = u.i64;
		}
		break;
	case CO_DEFTYPE_INTEGER64:
		chars = lex_c99_i64(cp, end, NULL, &u.i64);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.i64 == INT64_MIN)
				diag_if(DIAG_WARNING, get_errc(), at,
						"64-bit signed integer underflow");
			else if (get_errnum() == ERRNUM_RANGE
					&& u.i64 == INT64_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"64-bit signed integer overflow");
			if (val)
				*(co_integer64_t *)val = u.i64;
		}
		break;
	case CO_DEFTYPE_UNSIGNED24:
		chars = lex_c99_u32(cp, end, NULL, &u.u32);
		if (chars) {
			cp += chars;
			if (u.u32 > CO_UNSIGNED24_MAX) {
				u.u32 = CO_UNSIGNED24_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"24-bit unsigned integer overflow");
			}
			if (val)
				*(co_unsigned24_t *)val = u.u32;
		}
		break;
	case CO_DEFTYPE_UNSIGNED40:
		chars = lex_c99_u64(cp, end, NULL, &u.u64);
		if (chars) {
			cp += chars;
			if (u.u64 > CO_UNSIGNED40_MAX) {
				u.u64 = CO_UNSIGNED40_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"40-bit unsigned integer overflow");
			}
			if (val)
				*(co_unsigned40_t *)val = u.u64;
		}
		break;
	case CO_DEFTYPE_UNSIGNED48:
		chars = lex_c99_u64(cp, end, NULL, &u.u64);
		if (chars) {
			cp += chars;
			if (u.u64 > CO_UNSIGNED48_MAX) {
				u.u64 = CO_UNSIGNED48_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"48-bit unsigned integer overflow");
			}
			if (val)
				*(co_unsigned48_t *)val = u.u64;
		}
		break;
	case CO_DEFTYPE_UNSIGNED56:
		chars = lex_c99_u64(cp, end, NULL, &u.u64);
		if (chars) {
			cp += chars;
			if (u.u64 > CO_UNSIGNED56_MAX) {
				u.u64 = CO_UNSIGNED56_MAX;
				set_errnum(ERRNUM_RANGE);
				diag_if(DIAG_WARNING, get_errc(), at,
						"56-bit unsigned integer overflow");
			}
			if (val)
				*(co_unsigned56_t *)val = u.u64;
		}
		break;
	case CO_DEFTYPE_UNSIGNED64:
		chars = lex_c99_u64(cp, end, NULL, &u.u64);
		if (chars) {
			cp += chars;
			if (get_errnum() == ERRNUM_RANGE && u.u64 == UINT64_MAX)
				diag_if(DIAG_WARNING, get_errc(), at,
						"64-bit unsigned integer overflow");
			if (val)
				*(co_unsigned64_t *)val = u.u64;
		}
		break;
	default:
		diag_if(DIAG_ERROR, 0, at, "cannot parse value of type 0x%04X",
				type);
		break;
	}

	return floc_lex(at, begin, cp);
}

size_t
co_val_print(co_unsigned16_t type, const void *val, char **pbegin, char *end)
{
	if (co_type_is_array(type)) {
		const void *ptr = co_val_addressof(type, val);
		size_t n = co_val_sizeof(type, val);
		if (!ptr || !n)
			return 0;
		switch (type) {
		case CO_DEFTYPE_VISIBLE_STRING:
			return print_c99_str(pbegin, end, ptr, n);
		case CO_DEFTYPE_OCTET_STRING: {
			size_t chars = 0;
			for (const uint8_t *os = ptr; n; n--, os++) {
				chars += print_char(
						pbegin, end, xtoc(*os >> 4));
				chars += print_char(pbegin, end, xtoc(*os));
			}
			return chars;
		}
		case CO_DEFTYPE_UNICODE_STRING: {
			char16_t *us = NULL;
			if (!co_val_copy(type, &us, val) && !us)
				return 0;
			assert(us);
			for (size_t i = 0; i + 1 < n; i += 2)
				us[i / 2] = htole16(us[i / 2]);
			size_t chars = print_base64(pbegin, end, us, n);
			co_array_free(&us);
			return chars;
		}
		case CO_DEFTYPE_DOMAIN:
			return print_base64(pbegin, end, ptr, n);
		default:
			// We can never get here.
			return 0;
		}
	} else {
		const union co_val *u = val;
		assert(u);
		switch (type) {
		case CO_DEFTYPE_BOOLEAN:
			return print_c99_u8(pbegin, end, !!u->b);
		case CO_DEFTYPE_INTEGER8:
			return print_c99_i8(pbegin, end, u->i8);
		case CO_DEFTYPE_INTEGER16:
			return print_c99_i16(pbegin, end, u->i16);
		case CO_DEFTYPE_INTEGER32:
			return print_c99_i32(pbegin, end, u->i32);
		case CO_DEFTYPE_UNSIGNED8:
			return print_fmt(pbegin, end, "0x%02" PRIx8, u->u8);
		case CO_DEFTYPE_UNSIGNED16:
			return print_fmt(pbegin, end, "0x%04" PRIx16, u->u16);
		case CO_DEFTYPE_UNSIGNED32:
			return print_fmt(pbegin, end, "0x%08" PRIx32, u->u32);
		case CO_DEFTYPE_REAL32:
			return print_c99_u32(pbegin, end, u->u32);
		case CO_DEFTYPE_TIME_OF_DAY:
		case CO_DEFTYPE_TIME_DIFF: {
			size_t chars = 0;
			chars += print_c99_u16(pbegin, end, u->t.days);
			chars += print_char(pbegin, end, ' ');
			chars += print_c99_u32(pbegin, end, u->t.ms);
			return chars;
		}
		case CO_DEFTYPE_INTEGER24:
			return print_c99_i32(pbegin, end, u->i24);
		case CO_DEFTYPE_REAL64:
			return print_fmt(pbegin, end, "0x%016" PRIx64, u->u64);
		case CO_DEFTYPE_INTEGER40:
			return print_c99_i64(pbegin, end, u->i40);
		case CO_DEFTYPE_INTEGER48:
			return print_c99_i64(pbegin, end, u->i48);
		case CO_DEFTYPE_INTEGER56:
			return print_c99_i64(pbegin, end, u->i56);
		case CO_DEFTYPE_INTEGER64:
			return print_c99_i64(pbegin, end, u->i64);
		case CO_DEFTYPE_UNSIGNED24:
			return print_fmt(pbegin, end, "0x%06" PRIx32, u->u24);
		case CO_DEFTYPE_UNSIGNED40:
			return print_fmt(pbegin, end, "0x%010" PRIx64, u->u40);
		case CO_DEFTYPE_UNSIGNED48:
			return print_fmt(pbegin, end, "0x%012" PRIx64, u->u48);
		case CO_DEFTYPE_UNSIGNED56:
			return print_fmt(pbegin, end, "0x%014" PRIx64, u->u56);
		case CO_DEFTYPE_UNSIGNED64:
			return print_fmt(pbegin, end, "0x%016" PRIx64, u->u64);
		default: set_errnum(ERRNUM_INVAL); return 0;
		}
	}
}

static int
co_array_alloc(void *val, size_t size)
{
	assert(val);

	if (size) {
		// cppcheck-suppress AssignmentAddressToInteger
		char *ptr = calloc(1, CO_ARRAY_OFFSET + size);
		if (!ptr) {
			set_errc(errno2c(errno));
			return -1;
		}
		*(char **)val = ptr + CO_ARRAY_OFFSET;
	} else {
		*(char **)val = NULL;
	}

	return 0;
}

static void
co_array_free(void *val)
{
	assert(val);

	char *ptr = *(char **)val;
	if (ptr)
		free(ptr - CO_ARRAY_OFFSET);
}

static void
co_array_init(void *val, size_t size)
{
	assert(val);

	char *ptr = *(char **)val;
	assert(!size || ptr);
	if (ptr)
		*(size_t *)(ptr - CO_ARRAY_OFFSET) = size;
}

static void
co_array_fini(void *val)
{
	assert(val);

	*(char **)val = NULL;
}

static size_t
co_array_sizeof(const void *val)
{
	assert(val);

	const char *ptr = *(const char **)val;
	return ptr ? *(const size_t *)(ptr - CO_ARRAY_OFFSET) : 0;
}

static size_t
str16len(const char16_t *s)
{
	const char16_t *cp = s;
	for (; *cp; cp++)
		;
	return cp - s;
}

static char16_t *
str16ncpy(char16_t *dst, const char16_t *src, size_t n)
{
	char16_t *cp = dst;
	for (; n && *src; n--)
		*cp++ = *src++;
	while (n--)
		*cp++ = 0;

	return dst;
}

static int
str16ncmp(const char16_t *s1, const char16_t *s2, size_t n)
{
	int result = 0;
	while (n-- && !(result = *s1 - *s2++) && *s1++)
		;
	return result;
}
