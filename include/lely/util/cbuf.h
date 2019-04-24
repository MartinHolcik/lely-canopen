/**@file
 * This header file is part of the utilities library; it contains the circular
 * buffer declarations.
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

#ifndef LELY_UTIL_CBUF_H_
#define LELY_UTIL_CBUF_H_

#include <lely/util/util.h>

#include <stddef.h>
#include <string.h>

#ifndef LELY_UTIL_CBUF_INLINE
#define LELY_UTIL_CBUF_INLINE static inline
#endif

/// A circular buffer.
struct cbuf {
	/// A pointer to the allocated memory for the buffer.
	char *ptr;
	/**
	 * The total size (in bytes) of the buffer, including the unused byte
	 * used to distinguish between a full and an empty buffer.
	 */
	size_t size;
	/**
	 * The offset (with respect to #ptr) of the first byte available for
	 * reading (and two past the last byte available for writing, modulo
	 * #size).
	 */
	size_t begin;
	/**
	 * The offset (with respect to #ptr) of one past the last byte available
	 * for reading (and the first byte available for writing, modulo #size).
	 */
	size_t end;
};

/// The static initializer for struct #cbuf.
#define CBUF_INIT \
	{ \
		NULL, 0, 0, 0 \
	}

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes a circular buffer.
 *
 * @param buf  a pointer to an uninitialized circular buffer.
 * @param size the size (in bytes) of the buffer, excluding the unused byte used
 *             to distinguish between a full and an empty buffer.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see cbuf_fini()
 */
int cbuf_init(struct cbuf *buf, size_t size);

/// Finalizes a circular buffer. @see cbuf_init()
void cbuf_fini(struct cbuf *buf);

/// Returns 1 if the circular buffer is empty and 0 if not.
LELY_UTIL_CBUF_INLINE int cbuf_empty(const struct cbuf *buf);

/// Returns the total number of bytes written to a circular buffer.
LELY_UTIL_CBUF_INLINE size_t cbuf_size(const struct cbuf *buf);

/**
 * Returns the number of unused bytes remaining in a circular buffer, excluding
 * the byte used to distinguish between a full and an empty buffer.
 */
LELY_UTIL_CBUF_INLINE size_t cbuf_capacity(const struct cbuf *buf);

/// Clears a circular buffer. @see cbuf_flush()
LELY_UTIL_CBUF_INLINE void cbuf_clear(struct cbuf *buf);

/**
 * Attempts to read at most <b>n</b> bytes from a circular buffer into the
 * memory region at <b>ptr</b>.
 *
 * @returns the number of bytes read.
 */
size_t cbuf_read(struct cbuf *buf, void *ptr, size_t n);

/**
 * Attempts to write <b>n</b> from the memory region at <b>ptr</b> to a circular
 * buffer.
 *
 * @returns the number of bytes written.
 */
size_t cbuf_write(struct cbuf *buf, const void *ptr, size_t n);

inline int
cbuf_empty(const struct cbuf *buf)
{
	return buf->begin == buf->end;
}

inline size_t
cbuf_size(const struct cbuf *buf)
{
	return (buf->end - buf->begin) % buf->size;
}

inline size_t
cbuf_capacity(const struct cbuf *buf)
{
	return (buf->begin - buf->end - 1) % buf->size;
}

inline void
cbuf_clear(struct cbuf *buf)
{
	buf->begin = buf->end = 0;
}

#ifdef __cplusplus
}
#endif

#endif // !LELY_UTIL_CBUF_H_
