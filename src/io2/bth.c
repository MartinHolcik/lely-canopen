/**@file
 * This header file is part of the I/O library; it contains the implementation
 * of the Bluetooth address functions.
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
#include <lely/io2/bth.h>
#include <lely/util/errnum.h>
#include <lely/util/lex.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int
io_pton_bth(const char *str, unsigned char bytes[6])
{
	assert(str);
	assert(bytes);

	for (int i = 0; i < 6; i++) {
		int j, val = 0;
		for (j = 0; j < 2 && isxdigit((unsigned char)str[j]); j++)
			val = (val << 4) | ctox((unsigned char)str[j]);
		if (j != 2)
			goto error;
		bytes[i] = val;

		if (!str[j] && i == 5)
			break;
		if (i == 5)
			goto error;
		if (str[j] != ':')
			goto error;

		str += j + 1;
	}

	return 0;

error:
	set_errnum(ERRNUM_INVAL);
	return -1;
}

int
io_addr_is_bth_unspecified(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_BTH)
		return 0;
	assert(addr->len == sizeof(struct io_addr_bth));
	const struct io_addr_bth *bth = (const struct io_addr_bth *)addr;

	return io_addr_bth_to_uint(bth) == 0;
}

void
io_addr_bth_set_any(struct io_addr_bth *addr)
{
	assert(addr);

	*addr = (struct io_addr_bth)IO_ADDR_BTH_INIT;
}

void
io_addr_bth_set_from_uint(struct io_addr_bth *addr, uint_least64_t val)
{
	assert(addr);

	*addr = (struct io_addr_bth)IO_ADDR_BTH_INIT;
	for (int i = 0; i < 6; i++)
		addr->bytes[i] = (val >> ((5 - i) * 8)) & 0xff;
}

void
io_addr_bth_set_from_bytes(
		struct io_addr_bth *addr, const unsigned char bytes[6])
{
	assert(addr);

	*addr = (struct io_addr_bth)IO_ADDR_BTH_INIT;
	memcpy(addr->bytes, bytes, 6);
}

int
io_addr_bth_set_from_string(struct io_addr_bth *addr, const char *str)
{
	unsigned char bytes[6] = { 0 };
	if (io_pton_bth(str, bytes) == -1)
		return -1;

	io_addr_bth_set_from_bytes(addr, bytes);

	return 0;
}

uint_least64_t
io_addr_bth_to_uint(const struct io_addr_bth *addr)
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_bth));
	assert(addr->family == IO_ADDR_BTH);

	uint_least64_t val = 0;
	for (int i = 0; i < 6; i++)
		val |= (uint_least64_t)addr->bytes[i] << ((5 - i) * 8);
	return val;
}

void
io_addr_bth_to_bytes(const struct io_addr_bth *addr, unsigned char bytes[6])
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_bth));
	assert(addr->family == IO_ADDR_BTH);
	assert(bytes);

	memcpy(bytes, addr->bytes, 6);
}

void
io_addr_bth_to_string(const struct io_addr_bth *addr, char *str)
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_bth));
	assert(addr->family == IO_ADDR_BTH);
	assert(str);

	const unsigned char *bp = addr->bytes;
	snprintf(str, IO_ADDR_BTH_STRLEN, "%02X:%02X:%02X:%02X:%02X:%02X",
			bp[0], bp[1], bp[2], bp[3], bp[4], bp[5]);
}
