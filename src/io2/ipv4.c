/**@file
 * This header file is part of the I/O library; it contains the implementation
 * of the IPv4 address functions.
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
#include <lely/io2/ipv4.h>
#include <lely/util/errnum.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int
io_pton_ipv4(const char *str, unsigned char bytes[4])
{
	assert(str);
	assert(bytes);

	for (int i = 0; i < 4; i++) {
		int j, val = 0;
		for (j = 0; j < 3 && isdigit((unsigned char)str[j]); j++)
			val = val * 10 + (str[j] - '0');
		if (!j || (j > 1 && str[0] == '0') || val > 255)
			goto error;
		bytes[i] = val;

		if (!str[j] && i == 3)
			break;
		if (i == 3)
			goto error;
		if (str[j] != '.')
			goto error;

		str += j + 1;
	}

	return 0;

error:
	set_errnum(ERRNUM_INVAL);
	return -1;
}

int
io_addr_is_ipv4_unspecified(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV4)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv4));
	const struct io_addr_ipv4 *ipv4 = (const struct io_addr_ipv4 *)addr;

	return io_addr_ipv4_to_uint(ipv4) == 0;
}

int
io_addr_is_ipv4_loopback(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV4)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv4));
	const struct io_addr_ipv4 *ipv4 = (const struct io_addr_ipv4 *)addr;

	return (io_addr_ipv4_to_uint(ipv4) & UINT32_C(0xff000000))
			== UINT32_C(0x7f000000);
}

int
io_addr_is_ipv4_broadcast(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV4)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv4));
	const struct io_addr_ipv4 *ipv4 = (const struct io_addr_ipv4 *)addr;

	return io_addr_ipv4_to_uint(ipv4) == UINT32_C(0xffffffff);
}

int
io_addr_is_ipv4_multicast(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV4)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv4));
	const struct io_addr_ipv4 *ipv4 = (const struct io_addr_ipv4 *)addr;

	return (io_addr_ipv4_to_uint(ipv4) & UINT32_C(0xf0000000))
			== UINT32_C(0xe0000000);
}

void
io_addr_ipv4_set_any(struct io_addr_ipv4 *addr)
{
	assert(addr);

	*addr = (struct io_addr_ipv4)IO_ADDR_IPV4_INIT;
}

void
io_addr_ipv4_set_loopback(struct io_addr_ipv4 *addr)
{
	io_addr_ipv4_set_from_uint(addr, UINT32_C(0x7f000001));
}

void
io_addr_ipv4_set_broadcast(struct io_addr_ipv4 *addr)
{
	io_addr_ipv4_set_from_uint(addr, UINT32_C(0xffffffff));
}

void
io_addr_ipv4_set_from_uint(struct io_addr_ipv4 *addr, uint_least32_t val)
{
	assert(addr);

	*addr = (struct io_addr_ipv4)IO_ADDR_IPV4_INIT;
	for (int i = 0; i < 4; i++)
		addr->bytes[i] = (val >> ((3 - i) * 8)) & 0xff;
}

void
io_addr_ipv4_set_from_bytes(
		struct io_addr_ipv4 *addr, const unsigned char bytes[4])
{
	assert(addr);
	assert(bytes);

	*addr = (struct io_addr_ipv4)IO_ADDR_IPV4_INIT;
	memcpy(addr->bytes, bytes, 4);
}

int
io_addr_ipv4_set_from_string(struct io_addr_ipv4 *addr, const char *str)
{
	unsigned char bytes[4] = { 0 };
	if (io_pton_ipv4(str, bytes) == -1)
		return -1;

	io_addr_ipv4_set_from_bytes(addr, bytes);

	return 0;
}

uint_least32_t
io_addr_ipv4_to_uint(const struct io_addr_ipv4 *addr)
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_ipv4));
	assert(addr->family == IO_ADDR_IPV4);

	uint_least32_t val = 0;
	for (int i = 0; i < 4; i++)
		val |= (uint_least32_t)addr->bytes[i] << ((3 - i) * 8);
	return val;
}

void
io_addr_ipv4_to_bytes(const struct io_addr_ipv4 *addr, unsigned char bytes[4])
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_ipv4));
	assert(addr->family == IO_ADDR_IPV4);
	assert(bytes);

	memcpy(bytes, addr->bytes, 4);
}

void
io_addr_ipv4_to_string(const struct io_addr_ipv4 *addr, char *str)
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_ipv4));
	assert(addr->family == IO_ADDR_IPV4);
	assert(str);

	const unsigned char *bp = addr->bytes;
	snprintf(str, IO_ADDR_IPV4_STRLEN, "%d.%d.%d.%d", bp[0], bp[1], bp[2],
			bp[3]);
}
