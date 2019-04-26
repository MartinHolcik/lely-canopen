/**@file
 * This header file is part of the I/O library; it contains the TCP
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

#ifndef LELY_IO2_TCP_H_
#define LELY_IO2_TCP_H_

#include <lely/io2/endp.h>
#include <lely/io2/ipv4.h>
#include <lely/io2/ipv6.h>

/// The IANA protocol number for TCP.
#define IO_IPPROTO_TCP 6

/// An IPv4 TCP endpoint.
struct io_endp_ipv4_tcp {
	/// &#ipv4
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv4_tcp)`
	int len;
	/// #IO_IPPROTO_TCP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv4 network address.
	struct io_addr_ipv4 ipv4;
};

/**
 * The static initializer for #io_endp_ipv4_tcp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV4_TCP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv4, \
				sizeof(struct io_endp_ipv4_tcp), \
				IO_IPPROTO_TCP, 0, IO_ADDR_IPV4_INIT \
	}

union io_endp_ipv4_tcp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv4_tcp _ipv4_tcp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv4 TCP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV4_TCP_STRLEN (IO_ADDR_IPV4_STRLEN + 6)

/// An IPv6 TCP endpoint.
struct io_endp_ipv6_tcp {
	/// &#ipv6
	struct io_addr *addr;
	/// `sizeof(struct io_endp_ipv6_tcp)`
	int len;
	/// #IO_IPPROTO_TCP
	int protocol;
	/// The port number.
	uint_least16_t port;
	/// The IPv6 network address.
	struct io_addr_ipv6 ipv6;
};

/**
 * The static initializer for #io_endp_ipv6_tcp. <b>self</b> MUST be the address
 * of the struct being initialized.
 */
#define IO_ENDP_IPV6_TCP_INIT(self) \
	{ \
		(struct io_addr *)&(self)->ipv6, \
				sizeof(struct io_endp_ipv6_tcp), \
				IO_IPPROTO_TCP, 0, IO_ADDR_IPV6_INIT \
	}

union io_endp_ipv6_tcp_ {
	struct io_endp _endp;
	struct io_endp_storage _storage;
	struct io_endp_ipv6_tcp _ipv6_tcp;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv6 TCP endpoint, including the terminating null byte.
 */
#define IO_ENDP_IPV6_TCP_STRLEN (IO_ADDR_IPV6_STRLEN + 8)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates an IPv4 TCP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv4_tcp_to_string()
 */
int io_endp_ipv4_tcp_set_from_string(
		struct io_endp_ipv4_tcp *endp, const char *str);

/**
 * Stores a text representation of the IPv4 TCP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV4_TCP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv4_tcp_to_string()
 */
void io_endp_ipv4_tcp_to_string(const struct io_endp_ipv4_tcp *endp, char *str);

/**
 * Creates an IPv6 TCP endpoint from the text representation at <b>str</b>. The
 * syntax MUST comply with
 * <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>. If not specified,
 * the port number will be 0.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_endp_ipv6_tcp_to_string()
 */
int io_endp_ipv6_tcp_set_from_string(
		struct io_endp_ipv6_tcp *endp, const char *str);

/**
 * Stores a text representation of the IPv6 TCP endpoint at <b>endp</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ENDP_IPV6_TCP_STRLEN characters. The text representation is created
 * according to <a href=https://tools.ietf.org/html/rfc3986">RFC 3986</a>.
 *
 * @see io_endp_ipv6_tcp_to_string()
 */
void io_endp_ipv6_tcp_to_string(const struct io_endp_ipv6_tcp *endp, char *str);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_TCP_H_
