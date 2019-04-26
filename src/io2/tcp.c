/**@file
 * This file is part of the I/O library; it exposes the abstract TCP socket
 * functions.
 *
 * @see lely/io2/tcp.h
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
#define LELY_IO_TCP_INLINE extern inline
#include <lely/io2/tcp.h>
#include <lely/util/errnum.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>

static int io_tcp_port_set_from_string(uint_least16_t *port, const char *str);

int
io_endp_ipv4_tcp_set_from_string(struct io_endp_ipv4_tcp *endp, const char *str)
{
	assert(str);
	assert(endp);

	*endp = (struct io_endp_ipv4_tcp)IO_ENDP_IPV4_TCP_INIT(endp);

	char buf[IO_ADDR_IPV4_STRLEN];
	char *cp = buf;
	while (*str && *str != ':')
		*cp++ = *str++;
	*cp++ = '\0';

	if (io_addr_ipv4_set_from_string(&endp->ipv4, buf) == -1)
		return -1;
	if (*str++ != ':')
		return 0;
	return io_tcp_port_set_from_string(&endp->port, str);
}

void
io_endp_ipv4_tcp_to_string(const struct io_endp_ipv4_tcp *endp, char *str)
{
	assert(endp);
	assert(endp->protocol == IO_IPPROTO_TCP);

	io_addr_ipv4_to_string(&endp->ipv4, str);
	while (*str)
		str++;
	*str++ = ':';
	snprintf(str, 6, "%d", endp->port);
}

int
io_endp_ipv6_tcp_set_from_string(struct io_endp_ipv6_tcp *endp, const char *str)
{
	assert(str);
	assert(endp);

	*endp = (struct io_endp_ipv6_tcp)IO_ENDP_IPV6_TCP_INIT(endp);

	if (*str != '[')
		return io_addr_ipv6_set_from_string(&endp->ipv6, str);
	str++;

	char buf[IO_ADDR_IPV6_STRLEN];
	char *cp = buf;
	while (*str && *str != ']')
		*cp++ = *str++;
	*cp++ = '\0';
	if (*str++ != ']' || (*str && *str != ':')) {
		set_errnum(ERRNUM_INVAL);
		return -1;
	}

	if (io_addr_ipv6_set_from_string(&endp->ipv6, buf) == -1)
		return -1;
	if (*str++ != ':')
		return 0;
	return io_tcp_port_set_from_string(&endp->port, str);
}

void
io_endp_ipv6_tcp_to_string(const struct io_endp_ipv6_tcp *endp, char *str)
{
	assert(endp);
	assert(endp->protocol == IO_IPPROTO_TCP);

	*str++ = '[';
	io_addr_ipv6_to_string(&endp->ipv6, str);
	while (*str)
		str++;
	*str++ = ']';
	*str++ = ':';
	snprintf(str, 6, "%d", endp->port);
}

static int
io_tcp_port_set_from_string(uint_least16_t *port, const char *str)
{
	assert(port);
	assert(str);

	unsigned long val = 0;
	int i;
	for (i = 0; i < 5 && isdigit((unsigned char)str[i]); i++)
		val = val * 10 + (str[i] - '0');
	if (!i || (i > 0 && str[0] == '0') || val > UINT16_MAX
			|| str[i] != '\0') {
		set_errnum(ERRNUM_INVAL);
		return -1;
	}
	*port = val;

	return 0;
}
