/**@file
 * This header file is part of the I/O library; it contains the IPv6 address
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

#ifndef LELY_IO2_IPV6_H_
#define LELY_IO2_IPV6_H_

#include <lely/io2/addr.h>

#include <stdint.h>

/// An IPv6 address.
#define IO_ADDR_IPV6 3

/// An IPv6 address
struct io_addr_ipv6 {
	/// `sizeof(struct io_addr_ipv6)`
	unsigned short len;
	/// #IO_ADDR_IPV6
	unsigned short family;
	/// The IPv6 address in network byte order.
	unsigned char bytes[16];
	/// The scope identifier.
	uint_least32_t scope_id;
};

/// The static initializer for #io_addr_ipv6.
#define IO_ADDR_IPV6_INIT \
	{ \
		sizeof(struct io_addr_ipv6), IO_ADDR_IPV6, { 0 }, 0 \
	}

union io_addr_ipv6_ {
	struct io_addr _addr;
	struct io_addr_ipv6 _ipv6;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv6 network address, including the terminating null byte.
 */
#define IO_ADDR_IPV6_STRLEN 46

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts an IPv6 address from text to binary forms as if by POSIX
 * `inet_pton(AF_INET6, str, bytes)`.
 */
int io_pton_ipv6(const char *str, unsigned char bytes[16]);

/**
 * Returns 1 if *<b>addr</b> points to an unspecified IPv6 address and 0 if not.
 */
int io_addr_is_ipv6_unspecified(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv6 loopback address and 0 if not.
int io_addr_is_ipv6_loopback(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv6 multicast address and 0 if not.
int io_addr_is_ipv6_multicast(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 unicast link-local address and 0
 * if not.
 */
int io_addr_is_ipv6_linklocal(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 unicast site-local address and 0
 * if not.
 */
int io_addr_is_ipv6_sitelocal(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv4 mapped address and 0 if not.
int io_addr_is_ipv6_v4mapped(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv4-compatible address and 0 if not.
int io_addr_is_ipv6_v4compat(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 multicast node-local address and
 * 0 if not.
 */
int io_addr_is_ipv6_mc_nodelocal(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 multicast link-local address and
 * 0 if not.
 */
int io_addr_is_ipv6_mc_linklocal(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 multicast site-local address and
 * 0 if not.
 */
int io_addr_is_ipv6_mc_sitelocal(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 multicast organization-local
 * address and 0 if not.
 */
int io_addr_is_ipv6_mc_orglocal(const struct io_addr *addr);

/**
 * Returns 1 if *<b>addr</b> points to an IPv6 multicast global address and 0 if
 * not.
 */
int io_addr_is_ipv6_mc_global(const struct io_addr *addr);

/// Stores an unspecified IPv6 address at <b>addr</b>.
void io_addr_ipv6_set_any(struct io_addr_ipv6 *addr);

/// Stores the IPv6 loopback address at <b>addr</b>.
void io_addr_ipv6_set_loopback(struct io_addr_ipv6 *addr);

/**
 * Creates an IPv6 address from a representation in network byte order.
 *
 * @see io_addr_ipv6_to_uint()
 */
void io_addr_ipv6_set_from_bytes(
		struct io_addr_ipv6 *addr, const unsigned char bytes[16]);

/**
 * Creates an IPv6 address from the text representation at <b>str</b>. The text
 * representation is converted as if by POSIX `inet_pton()` when invoked with
 * address family `AF_INET6`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_addr_ipv6_to_string()
 */
int io_addr_ipv6_set_from_string(struct io_addr_ipv6 *addr, const char *str);

/**
 * Stores a network byte order representation of the IPv6 address at <b>addr</b>
 * to the memory region at <b>bytes</b>.
 *
 * @pre io_addr_is_ipv6() returns 1.
 */
void io_addr_ipv6_to_bytes(
		const struct io_addr_ipv6 *addr, unsigned char bytes[16]);

/**
 * Stores a text representation of the IPv6 address at <b>addr</b> to the buffer
 * at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ADDR_IPV6_STRLEN characters. The text representation is created as if by
 * POSIX `inet_ntop()` when invoked with address family `AF_INET6`.
 *
 * @pre io_addr_is_ipv6() returns 1.
 */
void io_addr_ipv6_to_string(const struct io_addr_ipv6 *addr, char *str);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_IPV6_H_
