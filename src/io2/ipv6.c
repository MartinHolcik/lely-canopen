/**@file
 * This header file is part of the I/O library; it contains the implementation
 * of the IPv6 address functions.
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
#include <lely/io2/ipv6.h>
#include <lely/util/errnum.h>
#include <lely/util/lex.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IO_ADDR_IPV6_BYTES_ANY \
	((const unsigned char[16]){ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })

#define IO_ADDR_IPV6_BYTES_LOOPBACK \
	((const unsigned char[16]){ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 })

int
io_pton_ipv6(const char *str, unsigned char bytes[16])
{
	assert(str);
	assert(bytes);

	uint_least16_t ip[8] = { 0 };
	int is_v4compat = 0;

	if (*str == ':' && *++str != ':')
		goto error;

	int i, k = -1;
	for (i = 0;; i++) {
		if (str[0] == ':' && k < 0) {
			k = i;
			if (!*++str)
				break;
			if (i == 7)
				goto error;
			continue;
		}

		int j, val = 0;
		for (j = 0; j < 4 && isxdigit((unsigned char)str[j]); j++)
			val = val * 16 + ctox((unsigned char)str[j]);
		if (!j)
			goto error;
		ip[i] = val;

		if (!str[j] && (k >= 0 || i == 7))
			break;
		if (i == 7)
			goto error;
		if (str[j] != ':') {
			if (str[j] != '.' || (i < 6 && k < 0))
				goto error;
			is_v4compat = 1;
			i++;
			break;
		}

		str += j + 1;
	}

	if (k >= 0) {
		memmove(ip + k + 7 - i, ip + k, (i + 1 - k) * sizeof(*ip));
		for (int j = 0; j < 7 - i; j++)
			ip[k + j] = 0;
	}

	for (int j = 0; j < 8; j++) {
		*bytes++ = (ip[j] >> 8) & 0xff;
		*bytes++ = ip[j] & 0xff;
	}

	return is_v4compat ? io_pton_ipv4(str, bytes - 4) : 0;

error:
	set_errnum(ERRNUM_INVAL);
	return -1;
}

int
io_addr_is_ipv6_unspecified(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return !memcmp(ipv6->bytes, IO_ADDR_IPV6_BYTES_ANY, 16);
}

int
io_addr_is_ipv6_loopback(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return !memcmp(ipv6->bytes, IO_ADDR_IPV6_BYTES_LOOPBACK, 16);
}

int
io_addr_is_ipv6_multicast(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return ipv6->bytes[0] == 0xff;
}

int
io_addr_is_ipv6_linklocal(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[0] & 0xff) == 0xfe
			&& (ipv6->bytes[1] & 0xc0) == 0x80;
}

int
io_addr_is_ipv6_sitelocal(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[0] & 0xff) == 0xfe
			&& (ipv6->bytes[1] & 0xc0) == 0xc0;
}

int
io_addr_is_ipv6_v4mapped(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	if (memcmp(ipv6->bytes, IO_ADDR_IPV6_BYTES_ANY, 10))
		return 0;
	return ipv6->bytes[10] == 0xff && ipv6->bytes[11] == 0xff;
}

int
io_addr_is_ipv6_v4compat(const struct io_addr *addr)
{
	assert(addr);
	if (addr->family != IO_ADDR_IPV6)
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	if (memcmp(ipv6->bytes, IO_ADDR_IPV6_BYTES_ANY, 12))
		return 0;
	return !!memcmp(ipv6->bytes + 12, IO_ADDR_IPV6_BYTES_ANY, 4);
}

int
io_addr_is_ipv6_mc_nodelocal(const struct io_addr *addr)
{
	if (!io_addr_is_ipv6_multicast(addr))
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[1] & 0x0f) == 0x01;
}

int
io_addr_is_ipv6_mc_linklocal(const struct io_addr *addr)
{
	if (!io_addr_is_ipv6_multicast(addr))
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[1] & 0x0f) == 0x02;
}

int
io_addr_is_ipv6_mc_sitelocal(const struct io_addr *addr)
{
	if (!io_addr_is_ipv6_multicast(addr))
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[1] & 0x0f) == 0x05;
}

int
io_addr_is_ipv6_mc_orglocal(const struct io_addr *addr)
{
	if (!io_addr_is_ipv6_multicast(addr))
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[1] & 0x0f) == 0x08;
}

int
io_addr_is_ipv6_mc_global(const struct io_addr *addr)
{
	if (!io_addr_is_ipv6_multicast(addr))
		return 0;
	assert(addr->len == sizeof(struct io_addr_ipv6));
	const struct io_addr_ipv6 *ipv6 = (const struct io_addr_ipv6 *)addr;

	return (ipv6->bytes[1] & 0x0f) == 0x0e;
}

void
io_addr_ipv6_set_any(struct io_addr_ipv6 *addr)
{
	assert(addr);

	*addr = (struct io_addr_ipv6)IO_ADDR_IPV6_INIT;
}

void
io_addr_ipv6_set_loopback(struct io_addr_ipv6 *addr)
{
	io_addr_ipv6_set_from_bytes(addr, IO_ADDR_IPV6_BYTES_LOOPBACK);
}

void
io_addr_ipv6_set_from_bytes(
		struct io_addr_ipv6 *addr, const unsigned char bytes[16])
{
	assert(addr);

	*addr = (struct io_addr_ipv6)IO_ADDR_IPV6_INIT;
	memcpy(addr->bytes, bytes, 16);
}

int
io_addr_ipv6_set_from_string(struct io_addr_ipv6 *addr, const char *str)
{
	unsigned char bytes[16] = { 0 };
	if (io_pton_ipv6(str, bytes) == -1)
		return -1;

	io_addr_ipv6_set_from_bytes(addr, bytes);

	return 0;
}

void
io_addr_ipv6_to_bytes(const struct io_addr_ipv6 *addr, unsigned char bytes[16])
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_ipv6));
	assert(addr->family == IO_ADDR_IPV6);
	assert(bytes);

	memcpy(bytes, addr->bytes, 16);
}

void
io_addr_ipv6_to_string(const struct io_addr_ipv6 *addr, char *str)
{
	assert(addr);
	assert(addr->len == sizeof(struct io_addr_ipv6));
	assert(addr->family == IO_ADDR_IPV6);
	assert(str);

	const unsigned char *bp = addr->bytes;
	if (io_addr_is_ipv6_v4mapped((const struct io_addr *)addr))
		snprintf(str, IO_ADDR_IPV6_STRLEN,
				"%x:%x:%x:%x:%x:%x:%d.%d.%d.%d",
				256 * bp[0] + bp[1], 256 * bp[2] + bp[3],
				256 * bp[4] + bp[5], 256 * bp[6] + bp[7],
				256 * bp[8] + bp[9], 256 * bp[10] + bp[11],
				bp[12], bp[13], bp[14], bp[15]);
	else
		snprintf(str, IO_ADDR_IPV6_STRLEN, "%x:%x:%x:%x:%x:%x:%x:%x",
				256 * bp[0] + bp[1], 256 * bp[2] + bp[3],
				256 * bp[4] + bp[5], 256 * bp[6] + bp[7],
				256 * bp[8] + bp[9], 256 * bp[10] + bp[11],
				256 * bp[12] + bp[13], 256 * bp[14] + bp[15]);

	int i = 0, j = 0;
	int len = 0;
	for (; str[i]; i++) {
		if (i && str[i] != ':')
			continue;
		int k = strspn(str + i, ":0");
		if (k - 2 > len) {
			len = k - 2;
			j = i;
		}
	}
	if (len > 1) {
		str[j] = str[j + 1] = ':';
		memmove(str + j + 2, str + j + 2 + len, i - j - len - 1);
	}
}
