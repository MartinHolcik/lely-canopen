/**@file
 * This file is part of the I/O library; it contains the implementation of the
 * I/O buffer functions.
 *
 * @see lely/io2/buf.h
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

#include "io2.h"
#include <lely/io2/buf.h>
#include <lely/libc/stdint.h>
#include <lely/util/errnum.h>

#include <assert.h>

ssize_t
io_buf_size(const struct io_buf *buf, int bufcnt)
{
	if (bufcnt < 1) {
		set_errnum(ERRNUM_INVAL);
		return -1;
	}
	assert(buf);

	ssize_t n = 0;
	for (int i = 0; i < bufcnt; i++) {
#if _WIN64
		if (n > SSIZE_MAX - buf[i].len) {
#else
		if (buf[i].len > SSIZE_MAX
				|| n > (ssize_t)(SSIZE_MAX - buf[i].len)) {
#endif
			set_errnum(ERRNUM_INVAL);
			return -1;
		}
		n += buf[i].len;
	}
	return n;
}
