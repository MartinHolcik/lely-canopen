/**@file
 * This file is part of the utilities library; it contains the implementation of
 * the circular buffer.
 *
 * @see lely/util/cbuf.h
 *
 * @copyright 2019 Lely Industries N.V.
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
#define LELY_UTIL_CBUF_INLINE extern inline
#include <lely/util/cbuf.h>
#include <lely/util/errnum.h>
#include <lely/util/util.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int
cbuf_init(struct cbuf *buf, size_t size)
{
	assert(buf);

	*buf = (struct cbuf)CBUF_INIT;

	buf->ptr = malloc(size + 1);
	if (!buf->ptr) {
		set_errc(errno2c(errno));
		return -1;
	}

	buf->size = size + 1;

	return 0;
}

void
cbuf_fini(struct cbuf *buf)
{
	assert(buf);

	free(buf->ptr);
}

size_t
cbuf_read(struct cbuf *buf, void *ptr, size_t n)
{
	assert(buf);
	assert(ptr || !n);

	if (!n)
		return 0;

	size_t size = cbuf_size(buf);
	n = MIN(n, size);

	if (buf->size - buf->begin >= n) {
		memcpy(ptr, buf->ptr + buf->begin, n);
		buf->begin += n;
	} else {
		size_t n1 = buf->size - buf->begin;
		memcpy(ptr, buf->ptr + buf->begin, n1);
		size_t n2 = n - n1;
		memcpy((char *)ptr + n1, buf->ptr, n2);
		buf->begin = n2;
	}

	return n;
}

size_t
cbuf_write(struct cbuf *buf, const void *ptr, size_t n)
{
	assert(buf);
	assert(ptr || !n);

	if (!n)
		return 0;

	size_t capacity = cbuf_capacity(buf);
	n = MIN(n, capacity);

	if (buf->size - buf->end >= n) {
		memcpy(buf->ptr + buf->end, ptr, n);
		buf->end += n;
	} else {
		size_t n1 = buf->size - buf->end;
		memcpy(buf->ptr + buf->end, ptr, n1);
		size_t n2 = n - n1;
		memcpy(buf->ptr, (const char *)ptr + n1, n2);
		buf->end = n2;
	}

	return n;
}
