/**@file
 * This header file is part of the I/O library; it contains the I/O buffer
 * declarations.
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

#ifndef LELY_IO2_BUF_H_
#define LELY_IO2_BUF_H_

#include <lely/libc/sys/types.h>

#include <stddef.h>

#if _WIN32

/**
 * A memory buffer suitable for read and write operations. The struct is
 * layout-compatible with WSABUF.
 */
struct io_buf {
	/// The size (in bytes) of the buffer.
	unsigned long len;
	/// The base address of the buffer.
	char *base;
};

/// The static initializer for #io_buf.
#define IO_BUF_INIT(base, len) \
	{ \
		(unsigned long)(len), (char *)(base) \
	}

#elif defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__)

/**
 * A memory buffer suitable for read and write operations. The struct is
 * layout-compatible with iovec.
 */
struct io_buf {
	/// The base address of the buffer.
	char *base;
	/// The size (in bytes) of the buffer.
	size_t len;
};

/// The static initializer for #io_buf.
#define IO_BUF_INIT(base, len) \
	{ \
		(char *)(base), (len) \
	}

#else //__linux__, __minix, __NetBSD__, __OpenBSD__

/**
 * A memory buffer suitable for read and write operations. The struct is
 * layout-compatible with iovec.
 */
struct io_buf {
	/// The base address of the buffer.
	void *base;
	/// The size (in bytes) of the buffer.
	size_t len;
};

/// The static initializer for #io_buf.
#define IO_BUF_INIT(base, len) \
	{ \
		(void *)(base), (len) \
	}

#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Computes total the size (in bytes) of an array of I/O buffers
 *
 * @param buf    an array of buffers.
 * @param bufcnt the number of buffers at <b>buf</b>.
 *
 * @returns the total size of the buffers, or -1 if the size would exceed
 * #SSIZE_MAX. In the latter case, the error number can be obtained with
 * get_errc().
 */
ssize_t io_buf_size(const struct io_buf *buf, int bufcnt);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_BUF_H_
