/**@file
 * This header file is part of the I/O library; it contains the IPv4 address
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

#ifndef LELY_IO2_IPV4_H_
#define LELY_IO2_IPV4_H_

#include <lely/io2/addr.h>

#include <stdint.h>

/// An IPv4 address.
#define IO_ADDR_IPV4 2

/// An IPv4 address
struct io_addr_ipv4 {
	/// `sizeof(struct io_addr_ipv4)`
	unsigned short len;
	/// #IO_ADDR_IPV4
	unsigned short family;
	/// The IPv4 address in network byte order.
	unsigned char bytes[4];
};

/// The static initializer for #io_addr_ipv4.
#define IO_ADDR_IPV4_INIT \
	{ \
		sizeof(struct io_addr_ipv4), IO_ADDR_IPV4, { 0 } \
	}

union io_addr_ipv4_ {
	struct io_addr _addr;
	struct io_addr_ipv4 _ipv4;
};

/**
 * The maximum number of bytes required to hold the text representation of an
 * IPv4 network address, including the terminating null byte.
 */
#define IO_ADDR_IPV4_STRLEN 16

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts an IPv4 address from text to binary forms as if by POSIX
 * `inet_pton(AF_INET, str, bytes)`.
 */
int io_pton_ipv4(const char *str, unsigned char bytes[4]);

/**
 * Returns 1 if *<b>addr</b> points to an unspecified IPv4 address and 0 if not.
 */
int io_addr_is_ipv4_unspecified(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv4 loopback address and 0 if not.
int io_addr_is_ipv4_loopback(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv4 broadcast address and 0 if not.
int io_addr_is_ipv4_broadcast(const struct io_addr *addr);

/// Returns 1 if *<b>addr</b> points to an IPv4 multicast address and 0 if not.
int io_addr_is_ipv4_multicast(const struct io_addr *addr);

/// Stores an unspecified IPv4 address at <b>addr</b>.
void io_addr_ipv4_set_any(struct io_addr_ipv4 *addr);

/// Stores the IPv4 loopback address at <b>addr</b>.
void io_addr_ipv4_set_loopback(struct io_addr_ipv4 *addr);

/// Stores the IPv4 broadcast address at <b>addr</b>.
void io_addr_ipv4_set_broadcast(struct io_addr_ipv4 *addr);

/**
 * Creates an IPv4 address from a representation in host byte order.
 *
 * @see io_addr_ipv4_to_uint()
 */
void io_addr_ipv4_set_from_uint(struct io_addr_ipv4 *addr, uint_least32_t val);

/**
 * Creates an IPv4 address from a representation in network byte order.
 *
 * @see io_addr_ipv4_to_uint()
 */
void io_addr_ipv4_set_from_bytes(
		struct io_addr_ipv4 *addr, const unsigned char bytes[4]);

/**
 * Creates an IPv4 address from the text representation at <b>str</b>. The text
 * representation is converted as if by POSIX `inet_pton()` when invoked with
 * address family `AF_INET`.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_addr_ipv4_to_string()
 */
int io_addr_ipv4_set_from_string(struct io_addr_ipv4 *addr, const char *str);

/**
 * Returns a representation of an IPv4 address in host byte order.
 *
 * @pre io_addr_is_ipv4() returns 1.
 *
 * @see io_addr_ipv4_set_from_uint()
 */
uint_least32_t io_addr_ipv4_to_uint(const struct io_addr_ipv4 *addr);

/**
 * Stores a network byte order representation of the IPv4 address at <b>addr</b>
 * to the memory region at <b>bytes</b>.
 *
 * @pre io_addr_is_ipv4() returns 1.
 *
 * @see io_addr_ipv4_set_from_bytes()
 */
void io_addr_ipv4_to_bytes(
		const struct io_addr_ipv4 *addr, unsigned char bytes[4]);

/**
 * Stores a text representation of the IPv4 address at <b>addr</b> to the buffer
 * at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ADDR_IPV4_STRLEN characters. The text representation is created as if by
 * POSIX `inet_ntop()` when invoked with address family `AF_INET`.
 *
 * @pre io_addr_is_ipv4() returns 1.
 *
 * @see io_addr_ipv4_set_from_string()
 */
void io_addr_ipv4_to_string(const struct io_addr_ipv4 *addr, char *str);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_IPV4_H_
