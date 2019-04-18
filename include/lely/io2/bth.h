/**@file
 * This header file is part of the I/O library; it contains the Bluetooth
 * address declarations.
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

#ifndef LELY_IO2_BTH_H_
#define LELY_IO2_BTH_H_

#include <lely/io2/addr.h>

#include <stdint.h>

/// A Bluetooth address.
#define IO_ADDR_BTH 4

/// A Bluetooth address
struct io_addr_bth {
	/// `sizeof(struct io_addr_bth)`
	unsigned short len;
	/// #IO_ADDR_BTH
	unsigned short family;
	/// The Bluetooth address in network byte order.
	unsigned char bytes[6];
};

/// The static initializer for #io_addr_bth.
#define IO_ADDR_BTH_INIT \
	{ \
		sizeof(struct io_addr_bth), IO_ADDR_BTH, { 0 } \
	}

union io_addr_bth_ {
	struct io_addr _addr;
	struct io_addr_bth _bth;
};

/**
 * The maximum number of bytes required to hold the text representation of a
 * Bluetooth device address, including the terminating null byte.
 */
#define IO_ADDR_BTH_STRLEN 18

#ifdef __cplusplus
extern "C" {
#endif

/// Converts a Bluetooth address from text to binary form.
int io_pton_bth(const char *str, unsigned char bytes[6]);

/**
 * Returns 1 if *<b>addr</b> points to an unspecified Bluetooth address and 0 if
 * not.
 */
int io_addr_is_bth_unspecified(const struct io_addr *addr);

/// Stores an unspecified Bluetooth address at <b>addr</b>.
void io_addr_bth_set_any(struct io_addr_bth *addr);

/**
 * Creates a Bluetooth address from a representation in host byte order.
 *
 * @see io_addr_bth_to_uint()
 */
void io_addr_bth_set_from_uint(struct io_addr_bth *addr, uint_least64_t val);

/**
 * Creates a Bluetooth address from a representation in little-endian byte
 * order.
 *
 * @see io_addr_bth_to_uint()
 */
void io_addr_bth_set_from_bytes(
		struct io_addr_bth *addr, const unsigned char bytes[6]);

/**
 * Creates a Bluetooth address from the text representation at <b>str</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained with get_errc().
 *
 * @see io_addr_bth_to_string()
 */
int io_addr_bth_set_from_string(struct io_addr_bth *addr, const char *str);

/**
 * Returns a representation of a Bluetooth address in host byte order.
 *
 * @pre io_addr_is_bth() returns 1.
 *
 * @see io_addr_bth_set_from_uint()
 */
uint_least64_t io_addr_bth_to_uint(const struct io_addr_bth *addr);

/**
 * Stores a little-endian byte order representation of the Bluetooth address at
 * <b>addr</b> to the memory region at <b>bytes</b>.
 *
 * @pre io_addr_is_bth() returns 1.
 */
void io_addr_bth_to_bytes(
		const struct io_addr_bth *addr, unsigned char bytes[6]);

/**
 * Stores a text representation of the Bluetooth address at <b>addr</b> to the
 * buffer at <b>str</b>. The buffer MUST be large enough to hold at least
 * #IO_ADDR_BTH_STRLEN characters.
 *
 * @pre io_addr_is_bth() returns 1.
 */
void io_addr_bth_to_string(const struct io_addr_bth *addr, char *str);

#ifdef __cplusplus
}
#endif

#endif // !LELY_IO2_BTH_H_
